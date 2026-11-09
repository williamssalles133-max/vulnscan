# VulnScan

Analisador de vulnerabilidades de apps Android para uso próprio. A aba Login só aponta fraquezas de autenticação e como corrigir; não testa senhas.

Use apenas em aplicativos próprios ou com autorização. O app não envia o APK para lugar nenhum: a varredura é local. A chave opcional da xAI fica criptografada no aparelho.

## Gerar o APK de debug

Requisitos: JDK 17+, Android SDK com `platforms;android-34` e `build-tools;34.0.0`.

```bash
export ANDROID_HOME="$HOME/Android/Sdk"   # ou o caminho do seu SDK
./gradlew assembleDebug
```

O APK sai em `app/build/outputs/apk/debug/app-debug.apk`.

Testes de lógica (sem emulador):

```bash
./gradlew testDebugUnitTest
```
