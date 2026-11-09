# VulnScan Pro

Analisador de vulnerabilidades de apps Android para uso próprio (versão 1.2.0). A aba Login só aponta fraquezas de autenticação e como corrigir; não testa senhas.

Use apenas em aplicativos próprios ou com autorização. O app não envia o APK para lugar nenhum: a varredura é local. A chave opcional da xAI fica criptografada no aparelho.

## Análise profunda (IA)

Na aba IA, **Análise Profunda (IA)** lê no aparelho o manifesto (pelo analisador já existente), as strings de `classes*.dex`, os nomes das bibliotecas `.so`, os assets e os recursos. O extrato é mascarado e limitado em tamanho antes de ir para a API xAI (grok-4.7, com fallback grok-4.3). A resposta agrupa achados por severidade e descreve o risco, a evidência e a correção. O app não altera, não injeta e não instrumenta outros aplicativos.

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
