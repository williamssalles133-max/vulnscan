package com.williams.vulnscan.ai;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class DeepAnalysisPromptTest {
    @Test
    public void asksForSeveritySectionsAndRefusesOffensiveHelp() {
        String prompt = DeepAnalysisPrompt.SYSTEM;
        assertTrue(prompt.contains("## Alto"));
        assertTrue(prompt.contains("## Médio"));
        assertTrue(prompt.contains("## Baixo"));
        assertTrue(prompt.contains("## Informativo"));
        assertTrue(prompt.contains("O que é"));
        assertTrue(prompt.contains("Por que é um risco"));
        assertTrue(prompt.contains("Evidência"));
        assertTrue(prompt.contains("Correção"));
        assertTrue(prompt.contains("exploit"));
        assertTrue(prompt.contains("injeção"));
        assertTrue(prompt.contains("bypass"));
        assertTrue(prompt.contains("recuse"));
        assertTrue(prompt.contains("mascarados"));
        String lower = prompt.toLowerCase(java.util.Locale.ROOT);
        assertFalse(lower.contains("aqui está o exploit"));
        assertFalse(lower.contains("payload de ataque:"));
        assertTrue(DeepAnalysisPrompt.USER_PREFIX.contains("defensiva"));
    }

    @Test
    public void recognizesSeverityHeadings() {
        assertTrue(SeverityHeading.parse("Alto") == SeverityHeading.Level.ALTO);
        assertTrue(SeverityHeading.parse("Médio") == SeverityHeading.Level.MEDIO);
        assertTrue(SeverityHeading.parse("Medio — rede") == SeverityHeading.Level.MEDIO);
        assertTrue(SeverityHeading.parse("Baixo") == SeverityHeading.Level.BAIXO);
        assertTrue(SeverityHeading.parse("Informativo") == SeverityHeading.Level.INFO);
        assertTrue(SeverityHeading.parse("Info") == SeverityHeading.Level.INFO);
        assertNull(SeverityHeading.parse("Correção"));
        assertNull(SeverityHeading.parse(null));
    }
}
