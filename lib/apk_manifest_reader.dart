import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

class ApkManifest {
  const ApkManifest({
    required this.xml,
    this.packageName,
    this.versionName,
    this.targetSdk,
  });

  final String xml;
  final String? packageName;
  final String? versionName;
  final int? targetSdk;
}

class ApkManifestReader {
  static ApkManifest read(Uint8List apkBytes) {
    final manifestBytes = _readZipEntry(apkBytes, 'AndroidManifest.xml');
    if (manifestBytes == null) {
      throw const FormatException(
        'AndroidManifest.xml was not found in this APK.',
      );
    }

    return readManifestBytes(manifestBytes);
  }

  static ApkManifest readManifestBytes(Uint8List manifestBytes) {
    final xml = _BinaryXmlDecoder(manifestBytes).decode();
    return ApkManifest(
      xml: xml,
      packageName: _attribute(xml, 'package'),
      versionName: _attribute(xml, 'android:versionName'),
      targetSdk: int.tryParse(
        _attribute(xml, 'android:targetSdkVersion') ?? '',
      ),
    );
  }

  static String? _attribute(String xml, String name) {
    final escaped = RegExp.escape(name);
    return RegExp('$escaped="([^"]*)"').firstMatch(xml)?.group(1);
  }

  static Uint8List? _readZipEntry(Uint8List bytes, String targetName) {
    final data = ByteData.sublistView(bytes);
    final eocdOffset = _findEndOfCentralDirectory(data);
    if (eocdOffset < 0) {
      throw const FormatException(
        'The selected file is not a valid APK/ZIP file.',
      );
    }

    final entryCount = data.getUint16(eocdOffset + 10, Endian.little);
    final centralDirectoryOffset = data.getUint32(
      eocdOffset + 16,
      Endian.little,
    );
    var cursor = centralDirectoryOffset;

    for (var i = 0; i < entryCount; i++) {
      if (data.getUint32(cursor, Endian.little) != 0x02014b50) {
        throw const FormatException('APK central directory is damaged.');
      }

      final method = data.getUint16(cursor + 10, Endian.little);
      final compressedSize = data.getUint32(cursor + 20, Endian.little);
      final fileNameLength = data.getUint16(cursor + 28, Endian.little);
      final extraLength = data.getUint16(cursor + 30, Endian.little);
      final commentLength = data.getUint16(cursor + 32, Endian.little);
      final localHeaderOffset = data.getUint32(cursor + 42, Endian.little);
      final name = utf8.decode(
        bytes.sublist(cursor + 46, cursor + 46 + fileNameLength),
      );

      if (name == targetName) {
        final localNameLength = data.getUint16(
          localHeaderOffset + 26,
          Endian.little,
        );
        final localExtraLength = data.getUint16(
          localHeaderOffset + 28,
          Endian.little,
        );
        final start =
            localHeaderOffset + 30 + localNameLength + localExtraLength;
        final compressed = bytes.sublist(start, start + compressedSize);

        if (method == 0) {
          return Uint8List.fromList(compressed);
        }
        if (method == 8) {
          return Uint8List.fromList(ZLibDecoder(raw: true).convert(compressed));
        }
        throw FormatException('Unsupported APK compression method: $method.');
      }

      cursor += 46 + fileNameLength + extraLength + commentLength;
    }

    return null;
  }

  static int _findEndOfCentralDirectory(ByteData data) {
    final minOffset = (data.lengthInBytes - 0xffff - 22).clamp(
      0,
      data.lengthInBytes,
    );
    for (var offset = data.lengthInBytes - 22; offset >= minOffset; offset--) {
      if (data.getUint32(offset, Endian.little) == 0x06054b50) {
        return offset;
      }
    }
    return -1;
  }
}

class _BinaryXmlDecoder {
  _BinaryXmlDecoder(Uint8List bytes) : _data = ByteData.sublistView(bytes);

  final ByteData _data;
  final _strings = <String>[];
  final _output = StringBuffer();
  int _depth = 0;

  String decode() {
    if (_u16(0) != 0x0003) {
      throw const FormatException('APK manifest is not Android binary XML.');
    }

    var offset = _u16(2);
    while (offset < _data.lengthInBytes) {
      final type = _u16(offset);
      final size = _u32(offset + 4);

      if (type == 0x0001) {
        _readStringPool(offset);
      } else if (type == 0x0102) {
        _readStartElement(offset);
      } else if (type == 0x0103) {
        _readEndElement(offset);
      }

      if (size <= 0) {
        break;
      }
      offset += size;
    }

    return _output.toString();
  }

  void _readStringPool(int offset) {
    final stringCount = _u32(offset + 8);
    final flags = _u32(offset + 16);
    final stringsStart = offset + _u32(offset + 20);
    final utf8Pool = (flags & 0x00000100) != 0;

    for (var i = 0; i < stringCount; i++) {
      final stringOffset = stringsStart + _u32(offset + 28 + (i * 4));
      _strings.add(
        utf8Pool
            ? _readUtf8String(stringOffset)
            : _readUtf16String(stringOffset),
      );
    }
  }

  String _readUtf8String(int offset) {
    var cursor = offset;
    final utf16Length = _readLength8(cursor);
    cursor += utf16Length.bytes;
    final utf8Length = _readLength8(cursor);
    cursor += utf8Length.bytes;
    return utf8.decode(_bytes(cursor, utf8Length.value), allowMalformed: true);
  }

  String _readUtf16String(int offset) {
    var cursor = offset;
    final length = _readLength16(cursor);
    cursor += length.bytes;
    final units = <int>[];
    for (var i = 0; i < length.value; i++) {
      units.add(_u16(cursor + (i * 2)));
    }
    return String.fromCharCodes(units);
  }

  _Length _readLength8(int offset) {
    final first = _u8(offset);
    if ((first & 0x80) == 0) {
      return _Length(first, 1);
    }
    return _Length(((first & 0x7f) << 8) | _u8(offset + 1), 2);
  }

  _Length _readLength16(int offset) {
    final first = _u16(offset);
    if ((first & 0x8000) == 0) {
      return _Length(first, 2);
    }
    return _Length(((first & 0x7fff) << 16) | _u16(offset + 2), 4);
  }

  void _readStartElement(int offset) {
    final name = _string(_u32(offset + 20));
    final attributeStart = _u16(offset + 24);
    final attributeSize = _u16(offset + 26);
    final attributeCount = _u16(offset + 28);
    final attributes = <String>[];

    for (var i = 0; i < attributeCount; i++) {
      final attrOffset = offset + attributeStart + (i * attributeSize);
      final namespace = _string(_u32(attrOffset));
      final attrName = _string(_u32(attrOffset + 4));
      final rawValue = _u32(attrOffset + 8);
      final dataType = _u8(attrOffset + 15);
      final data = _u32(attrOffset + 16);
      final qualifiedName =
          namespace == 'http://schemas.android.com/apk/res/android'
          ? 'android:$attrName'
          : attrName;
      attributes.add(
        '$qualifiedName="${_escape(_value(rawValue, dataType, data))}"',
      );
    }

    _output.writeln(
      '${'  ' * _depth}<$name${attributes.isEmpty ? '' : ' ${attributes.join(' ')}'}>',
    );
    _depth++;
  }

  void _readEndElement(int offset) {
    _depth = (_depth - 1).clamp(0, 1000);
    final name = _string(_u32(offset + 20));
    _output.writeln('${'  ' * _depth}</$name>');
  }

  String _value(int rawValue, int dataType, int data) {
    if (rawValue != 0xffffffff) {
      return _string(rawValue);
    }
    return switch (dataType) {
      0x03 => _string(data),
      0x10 || 0x11 => '$data',
      0x12 => data == 0 ? 'false' : 'true',
      0x01 => '0x${data.toRadixString(16)}',
      _ => '$data',
    };
  }

  String _string(int index) {
    if (index == 0xffffffff || index < 0 || index >= _strings.length) {
      return '';
    }
    return _strings[index];
  }

  String _escape(String value) {
    return value
        .replaceAll('&', '&amp;')
        .replaceAll('"', '&quot;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;');
  }

  Uint8List _bytes(int offset, int length) =>
      Uint8List.sublistView(_data, offset, offset + length);
  int _u8(int offset) => _data.getUint8(offset);
  int _u16(int offset) => _data.getUint16(offset, Endian.little);
  int _u32(int offset) => _data.getUint32(offset, Endian.little);
}

class _Length {
  const _Length(this.value, this.bytes);

  final int value;
  final int bytes;
}
