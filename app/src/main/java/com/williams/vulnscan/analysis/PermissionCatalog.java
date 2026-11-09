package com.williams.vulnscan.analysis;

import android.content.pm.PermissionInfo;

import com.williams.vulnscan.model.Severity;

import java.util.HashMap;
import java.util.Map;

public final class PermissionCatalog {
    public static final class Assessment {
        public final Severity severity;
        public final String title;
        public final String explanation;
        public final boolean highlight;

        Assessment(Severity severity, String title, String explanation, boolean highlight) {
            this.severity = severity;
            this.title = title;
            this.explanation = explanation;
            this.highlight = highlight;
        }
    }

    private static final Map<String, Assessment> SPECIAL = new HashMap<>();

    static {
        high("android.permission.CAMERA", "CAMERA",
                "Acesso à câmera. Pode capturar imagem sem o usuário perceber se a tela não deixa isso claro.");
        high("android.permission.RECORD_AUDIO", "RECORD_AUDIO",
                "Acesso ao microfone. Áudio do ambiente pode ser gravado e enviado para fora do aparelho.");
        high("android.permission.ACCESS_FINE_LOCATION", "ACCESS_FINE_LOCATION",
                "Localização precisa (GPS). Revela onde o usuário está e, com histórico, a rotina dele.");
        high("android.permission.ACCESS_COARSE_LOCATION", "ACCESS_COARSE_LOCATION",
                "Localização aproximada. Ainda identifica bairro ou cidade e pode ser cruzada com outros dados.");
        high("android.permission.ACCESS_BACKGROUND_LOCATION", "ACCESS_BACKGROUND_LOCATION",
                "Localização em segundo plano, mesmo com o app fechado. É um dos acessos mais sensíveis do Android.");
        high("android.permission.READ_CONTACTS", "READ_CONTACTS",
                "Leitura da agenda. Nomes, telefones e e-mails podem sair do aparelho.");
        high("android.permission.WRITE_CONTACTS", "WRITE_CONTACTS",
                "Alteração da agenda. O app pode criar ou mudar contatos.");
        high("android.permission.GET_ACCOUNTS", "GET_ACCOUNTS",
                "Lista de contas do aparelho. Revela quais serviços o usuário usa.");
        high("android.permission.READ_SMS", "READ_SMS",
                "Leitura de SMS, incluindo códigos de verificação. Pode facilitar sequestro de conta.");
        high("android.permission.SEND_SMS", "SEND_SMS",
                "Envio de SMS. Pode gerar custo ou enviar mensagens sem um fluxo claro para o usuário.");
        high("android.permission.RECEIVE_SMS", "RECEIVE_SMS",
                "Recebimento de SMS. O app pode ler códigos e avisos que chegam por mensagem.");
        high("android.permission.RECEIVE_MMS", "RECEIVE_MMS",
                "Recebimento de MMS. Conteúdo de mensagem multimídia fica acessível ao app.");
        high("android.permission.READ_CALL_LOG", "READ_CALL_LOG",
                "Histórico de chamadas. Revela com quem o usuário fala e quando.");
        high("android.permission.WRITE_CALL_LOG", "WRITE_CALL_LOG",
                "Alteração do histórico de chamadas.");
        high("android.permission.CALL_PHONE", "CALL_PHONE",
                "Iniciar chamadas. Pode ligar sem abrir o discador.");
        high("android.permission.ANSWER_PHONE_CALLS", "ANSWER_PHONE_CALLS",
                "Atender chamadas. O app participa do fluxo de telefonia.");
        high("android.permission.PROCESS_OUTGOING_CALLS", "PROCESS_OUTGOING_CALLS",
                "Ver e interferir em chamadas de saída.");
        high("android.permission.REQUEST_INSTALL_PACKAGES", "REQUEST_INSTALL_PACKAGES",
                "Pode pedir a instalação de outros APKs. Combinada com download, abre caminho para sideload de pacote não desejado.");
        high("android.permission.SYSTEM_ALERT_WINDOW", "SYSTEM_ALERT_WINDOW",
                "Desenha por cima de outros apps. É a base clássica de ataque de overlay (tapjacking).");
        high("android.permission.QUERY_ALL_PACKAGES", "QUERY_ALL_PACKAGES",
                "Enxerga todos os apps instalados. Revela o perfil de uso do aparelho.");
        high("android.permission.PACKAGE_USAGE_STATS", "PACKAGE_USAGE_STATS",
                "Estatísticas de uso. Mostra quais apps são abertos e por quanto tempo.");
        high("android.permission.MANAGE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE",
                "Acesso amplo a todos os arquivos do armazenamento. Equivale a ler e escrever quase tudo que está no aparelho.");
        high("android.permission.BODY_SENSORS", "BODY_SENSORS",
                "Sensores corporais, como batimento. Dado de saúde no cliente exige cuidado extra.");
        high("android.permission.BODY_SENSORS_BACKGROUND", "BODY_SENSORS_BACKGROUND",
                "Sensores corporais em segundo plano.");
        high("android.permission.READ_CALENDAR", "READ_CALENDAR",
                "Leitura da agenda. Compromissos revelam rotina, locais e contatos.");
        high("android.permission.WRITE_CALENDAR", "WRITE_CALENDAR",
                "Alteração da agenda.");
        high("android.permission.INSTALL_PACKAGES", "INSTALL_PACKAGES",
                "Instalação silenciosa de pacotes. É permissão privilegiada; se estiver no manifesto, revise com atenção.");
        high("android.permission.READ_LOGS", "READ_LOGS",
                "Leitura de logs do sistema. Pode vazar tokens e dados que outros apps imprimem.");

        medium("android.permission.INTERNET", "INTERNET",
                "Comunicação de rede. Sozinha não é uma falha, mas é o caminho para vazamento de dados e para uso de chaves extraídas do APK.");
        medium("android.permission.READ_EXTERNAL_STORAGE", "READ_EXTERNAL_STORAGE",
                "Leitura do armazenamento compartilhado. Em versões antigas do Android alcança fotos e downloads de outros apps.");
        medium("android.permission.WRITE_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
                "Escrita no armazenamento compartilhado. Pode alterar ou criar arquivos visíveis para outros apps.");
        medium("android.permission.READ_MEDIA_IMAGES", "READ_MEDIA_IMAGES",
                "Acesso às fotos do aparelho.");
        medium("android.permission.READ_MEDIA_VIDEO", "READ_MEDIA_VIDEO",
                "Acesso aos vídeos do aparelho.");
        medium("android.permission.READ_MEDIA_AUDIO", "READ_MEDIA_AUDIO",
                "Acesso aos áudios do aparelho.");
        medium("android.permission.ACCESS_MEDIA_LOCATION", "ACCESS_MEDIA_LOCATION",
                "Localização embutida nas fotos.");
        medium("android.permission.READ_PHONE_STATE", "READ_PHONE_STATE",
                "Estado do telefone, incluindo identificadores. Ajuda a rastrear o aparelho.");
        medium("android.permission.READ_PHONE_NUMBERS", "READ_PHONE_NUMBERS",
                "Leitura do número de telefone da linha.");
        medium("android.permission.READ_BASIC_PHONE_STATE", "READ_BASIC_PHONE_STATE",
                "Estado básico do telefone, sem o identificador completo.");
        medium("android.permission.RECEIVE_BOOT_COMPLETED", "RECEIVE_BOOT_COMPLETED",
                "Executa código quando o aparelho liga. Útil para persistência; confirme se o app precisa disso.");
        medium("android.permission.WRITE_SETTINGS", "WRITE_SETTINGS",
                "Pode alterar configurações globais do sistema, se o usuário conceder.");
        medium("android.permission.BLUETOOTH_CONNECT", "BLUETOOTH_CONNECT",
                "Conecta a dispositivos Bluetooth próximos.");
        medium("android.permission.BLUETOOTH_SCAN", "BLUETOOTH_SCAN",
                "Varre Bluetooth. Pode estimar presença de dispositivos ao redor.");
        medium("android.permission.NEARBY_WIFI_DEVICES", "NEARBY_WIFI_DEVICES",
                "Dispositivos Wi-Fi próximos.");
        medium("android.permission.ACTIVITY_RECOGNITION", "ACTIVITY_RECOGNITION",
                "Reconhece atividade física (caminhada, veículo).");
        medium("android.permission.FOREGROUND_SERVICE_CAMERA", "FOREGROUND_SERVICE_CAMERA",
                "Serviço em primeiro plano com câmera. A câmera pode seguir ativa fora da tela principal.");
        medium("android.permission.FOREGROUND_SERVICE_MICROPHONE", "FOREGROUND_SERVICE_MICROPHONE",
                "Serviço em primeiro plano com microfone.");
        medium("android.permission.FOREGROUND_SERVICE_LOCATION", "FOREGROUND_SERVICE_LOCATION",
                "Serviço em primeiro plano com localização.");

        low("android.permission.POST_NOTIFICATIONS", "POST_NOTIFICATIONS",
                "Exibe notificações. Risco baixo, mas pode ser usada para phishing visual.");
        low("android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS", "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
                "Pede para ignorar otimização de bateria e continuar em segundo plano.");
        low("android.permission.SCHEDULE_EXACT_ALARM", "SCHEDULE_EXACT_ALARM",
                "Agenda alarmes exatos. Sozinha tem impacto pequeno.");
        low("android.permission.NFC", "NFC",
                "Usa NFC. O risco depende do que o app faz com as tags.");
        low("android.permission.BLUETOOTH_ADVERTISE", "BLUETOOTH_ADVERTISE",
                "Anuncia o aparelho via Bluetooth.");
    }

    private PermissionCatalog() {
    }

    public static Assessment assess(String permission, int protectionLevel) {
        Assessment special = SPECIAL.get(permission);
        if (special != null) {
            return special;
        }
        if (protectionLevel < 0) {
            return null;
        }
        int base = protectionLevel & PermissionInfo.PROTECTION_MASK_BASE;
        if (base == PermissionInfo.PROTECTION_DANGEROUS) {
            return new Assessment(
                    Severity.MEDIO,
                    shortName(permission),
                    "Permissão perigosa do Android. O sistema pede consentimento porque ela alcança dados ou funções sensíveis. Confira se o app realmente precisa dela.",
                    true);
        }
        return null;
    }

    public static String shortName(String permission) {
        if (permission == null) {
            return "";
        }
        int dot = permission.lastIndexOf('.');
        return dot >= 0 ? permission.substring(dot + 1) : permission;
    }

    private static void high(String name, String title, String explanation) {
        SPECIAL.put(name, new Assessment(Severity.ALTO, title, explanation, true));
    }

    private static void medium(String name, String title, String explanation) {
        SPECIAL.put(name, new Assessment(Severity.MEDIO, title, explanation, true));
    }

    private static void low(String name, String title, String explanation) {
        SPECIAL.put(name, new Assessment(Severity.BAIXO, title, explanation, true));
    }
}
