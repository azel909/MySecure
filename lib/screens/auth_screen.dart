import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../services/backend_api.dart';

const _gold = Color(0xFFF5B323);
const _ink = Color(0xFF06122E);
const _panel = Color(0xFF0D2355);
const _panelSoft = Color(0xFF14316F);
const _line = Color(0xFF31558E);
const _muted = Color(0xFFB7C7E7);

class AuthScreen extends StatefulWidget {
  const AuthScreen({required this.onAuthenticated, super.key});

  final ValueChanged<AuthSession> onAuthenticated;

  @override
  State<AuthScreen> createState() => _AuthScreenState();
}

class _AuthScreenState extends State<AuthScreen> {
  static const _prefs = MethodChannel('mysecure/preferences');

  final baseUrlController = TextEditingController(
    text: 'https://secure-droid.onrender.com',
  );
  final nameController = TextEditingController();
  final emailController = TextEditingController();
  final passwordController = TextEditingController();

  bool registerMode = false;
  bool loading = false;
  bool showConnectionSettings = false;

  @override
  void initState() {
    super.initState();
    _loadSavedBackendUrl();
  }

  Future<void> _loadSavedBackendUrl() async {
    try {
      final saved = await _prefs.invokeMethod<String>('getString', {
        'key': 'backend_url',
      });
      if (saved != null && saved.isNotEmpty && mounted) {
        baseUrlController.text = saved;
      }
    } catch (_) {
      // Keep the default URL if Android local storage is unavailable.
    }
  }

  @override
  void dispose() {
    baseUrlController.dispose();
    nameController.dispose();
    emailController.dispose();
    passwordController.dispose();
    super.dispose();
  }

  Future<void> submit() async {
    setState(() => loading = true);
    try {
      final api = BackendApi(baseUrlController.text.trim());
      final session = registerMode
          ? await api.register(
              name: nameController.text.trim(),
              email: emailController.text.trim(),
              password: passwordController.text,
            )
          : await api.login(
              email: emailController.text.trim(),
              password: passwordController.text,
            );
      widget.onAuthenticated(session);
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('$error'), backgroundColor: _panelSoft),
        );
      }
    } finally {
      if (mounted) {
        setState(() => loading = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: _ink,
      body: Stack(
        children: [
          const _AuthBackground(),
          SafeArea(
            child: Center(
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(22),
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 460),
                  child: Container(
                    padding: const EdgeInsets.all(18),
                    decoration: BoxDecoration(
                      color: _panel.withValues(alpha: 0.94),
                      borderRadius: BorderRadius.circular(18),
                      border: Border.all(color: _line),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        Image.asset(
                          'assets/branding/secure_logo.png',
                          height: 82,
                          fit: BoxFit.contain,
                          filterQuality: FilterQuality.high,
                        ),
                        const SizedBox(height: 14),
                        Text(
                          registerMode
                              ? 'Create Government Auditor Account'
                              : 'Government Auditor Login',
                          textAlign: TextAlign.center,
                          style: const TextStyle(
                            fontSize: 24,
                            fontWeight: FontWeight.w900,
                          ),
                        ),
                        const SizedBox(height: 8),
                        const Text(
                          'Authenticate before submitting government mobile compliance reports to the backend.',
                          textAlign: TextAlign.center,
                          style: TextStyle(color: _muted, height: 1.35),
                        ),
                        const SizedBox(height: 14),
                        Align(
                          alignment: Alignment.center,
                          child: TextButton.icon(
                            onPressed: loading
                                ? null
                                : () => setState(
                                    () => showConnectionSettings =
                                        !showConnectionSettings,
                                  ),
                            icon: Icon(
                              showConnectionSettings
                                  ? Icons.expand_less_rounded
                                  : Icons.tune_rounded,
                              size: 18,
                            ),
                            label: const Text('Connection settings'),
                          ),
                        ),
                        AnimatedCrossFade(
                          firstChild: const SizedBox.shrink(),
                          secondChild: Column(
                            children: [
                              const SizedBox(height: 8),
                              _AuthField(
                                label: 'Backend URL',
                                controller: baseUrlController,
                                icon: Icons.dns_outlined,
                              ),
                            ],
                          ),
                          crossFadeState: showConnectionSettings
                              ? CrossFadeState.showSecond
                              : CrossFadeState.showFirst,
                          duration: const Duration(milliseconds: 180),
                        ),
                        const SizedBox(height: 12),
                        if (registerMode)
                          _AuthField(
                            label: 'Name',
                            controller: nameController,
                            icon: Icons.badge_outlined,
                          ),
                        _AuthField(
                          label: 'Email',
                          controller: emailController,
                          icon: Icons.mail_outline,
                        ),
                        _AuthField(
                          label: 'Password',
                          controller: passwordController,
                          icon: Icons.lock_outline,
                          obscureText: true,
                        ),
                        const SizedBox(height: 8),
                        FilledButton.icon(
                          onPressed: loading ? null : submit,
                          icon: loading
                              ? const SizedBox(
                                  width: 18,
                                  height: 18,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2,
                                  ),
                                )
                              : Icon(
                                  registerMode
                                      ? Icons.person_add_alt_1
                                      : Icons.login,
                                ),
                          label: Text(registerMode ? 'Register' : 'Login'),
                          style: FilledButton.styleFrom(
                            backgroundColor: _gold,
                            foregroundColor: Colors.black,
                            minimumSize: const Size.fromHeight(50),
                          ),
                        ),
                        TextButton(
                          onPressed: loading
                              ? null
                              : () => setState(
                                  () => registerMode = !registerMode,
                                ),
                          child: Text(
                            registerMode
                                ? 'Already have an account? Login'
                                : 'Need an account? Register',
                          ),
                        ),
                        const SizedBox(height: 8),
                        const Text(
                          'Open connection settings only when the backend IP changes.',
                          textAlign: TextAlign.center,
                          style: TextStyle(color: _muted, fontSize: 12),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _AuthBackground extends StatefulWidget {
  const _AuthBackground();

  @override
  State<_AuthBackground> createState() => _AuthBackgroundState();
}

class _AuthBackgroundState extends State<_AuthBackground>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 9),
    )..repeat();
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Positioned.fill(
      child: AnimatedBuilder(
        animation: _controller,
        builder: (context, child) {
          return Stack(
            fit: StackFit.expand,
            children: [
              Image.asset(
                'assets/branding/login_background.png',
                fit: BoxFit.cover,
                alignment: Alignment.center,
                filterQuality: FilterQuality.high,
              ),
              DecoratedBox(
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    begin: Alignment.topCenter,
                    end: Alignment.bottomCenter,
                    colors: [
                      _ink.withValues(alpha: 0.18),
                      _ink.withValues(alpha: 0.04),
                      _ink.withValues(alpha: 0.30),
                    ],
                  ),
                ),
              ),
              CustomPaint(
                painter: _AuthMotionPainter(progress: _controller.value),
              ),
            ],
          );
        },
      ),
    );
  }
}

class _AuthMotionPainter extends CustomPainter {
  const _AuthMotionPainter({required this.progress});

  final double progress;

  @override
  void paint(Canvas canvas, Size size) {
    final blue = const Color(0xFF22A7FF);
    final scanPaint = Paint()
      ..shader = LinearGradient(
        begin: Alignment.centerLeft,
        end: Alignment.centerRight,
        colors: [
          Colors.transparent,
          blue.withValues(alpha: 0.18),
          Colors.transparent,
        ],
      ).createShader(Rect.fromLTWH(0, 0, size.width, 1))
      ..strokeWidth = 2;

    final scanY = (size.height + 120) * progress - 60;
    canvas.drawLine(Offset(0, scanY), Offset(size.width, scanY), scanPaint);

    final pulsePaint = Paint()
      ..color = _gold.withValues(alpha: 0.36)
      ..strokeWidth = 2.3
      ..strokeCap = StrokeCap.round;
    final bluePulsePaint = Paint()
      ..color = blue.withValues(alpha: 0.30)
      ..strokeWidth = 1.8
      ..strokeCap = StrokeCap.round;

    final bottom = size.height * 0.86;
    for (var i = 0; i < 5; i++) {
      final phase = (progress + i * 0.18) % 1;
      final x = size.width * (0.08 + phase * 0.84);
      final y = bottom + math.sin((phase + i) * math.pi * 2) * 12;
      canvas.drawLine(
        Offset(x - 34, y),
        Offset(x + 34, y - 16),
        bluePulsePaint,
      );
    }

    final goldPhase = (progress * 1.3) % 1;
    canvas.drawLine(
      Offset(size.width * (0.02 + goldPhase * 0.28), size.height * 0.10),
      Offset(size.width * (0.18 + goldPhase * 0.28), size.height * 0.01),
      pulsePaint,
    );

    final glowCenter = Offset(
      size.width * (0.26 + math.sin(progress * math.pi * 2) * 0.08),
      size.height * 0.12,
    );
    final glowPaint = Paint()
      ..shader =
          RadialGradient(
            colors: [blue.withValues(alpha: 0.20), Colors.transparent],
          ).createShader(
            Rect.fromCircle(center: glowCenter, radius: size.width * 0.5),
          );
    canvas.drawCircle(glowCenter, size.width * 0.5, glowPaint);
  }

  @override
  bool shouldRepaint(covariant _AuthMotionPainter oldDelegate) =>
      oldDelegate.progress != progress;
}

class _AuthField extends StatelessWidget {
  const _AuthField({
    required this.label,
    required this.controller,
    required this.icon,
    this.obscureText = false,
  });

  final String label;
  final TextEditingController controller;
  final IconData icon;
  final bool obscureText;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: TextField(
        controller: controller,
        obscureText: obscureText,
        style: const TextStyle(
          color: Color(0xFFEAF3FF),
          fontWeight: FontWeight.w700,
        ),
        decoration: InputDecoration(
          prefixIcon: Icon(icon, color: _gold),
          labelText: label,
          labelStyle: const TextStyle(color: _muted),
          filled: true,
          fillColor: _panelSoft,
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(12),
            borderSide: const BorderSide(color: _line),
          ),
          enabledBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(12),
            borderSide: const BorderSide(color: _line),
          ),
          focusedBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(12),
            borderSide: const BorderSide(color: _gold),
          ),
        ),
      ),
    );
  }
}
