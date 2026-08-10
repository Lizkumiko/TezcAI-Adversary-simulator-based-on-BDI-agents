// ================================================================================================
// Agente: agCredAccess.asl
// Version: 1.0.0
//
// Descripción: Agente BDI de acceso por credenciales.
//   MITRE ATT&CK: TA0006 Credential Access (T1110 Brute Force / T1078 Valid Accounts).
//   Recibe el handoff de agDiscovery al terminar el reconocimiento y delega en
//   credAgR la prueba de credenciales por defecto contra los servicios ya
//   descubiertos (no escanea nada nuevo, solo usa lo que networkAgR encontró).
//
// Flujo de ejecución:
//   1. start_cred[source(agDiscovery)] -> Delega en credAgR el escaneo de credenciales
//   2. cred_conf(Resultado) -> Recibe confirmación y cierra la fase
// ================================================================================================

fase(credenciales).

// ===========================================
// GOAL: Iniciar fase de acceso por credenciales
// Trigger: handoff de agDiscovery al finalizar el reconocimiento
// ===========================================
+!start_cred[source(agDiscovery)] <-
    .print("===========================================");
    .ev_phase("credenciales");
    .ev_goal_start("start_cred");
    .ev_delegation(credAgR, cred_scan);
    .send(credAgR, achieve, cred_scan("all")).

// ===========================================
// PLAN: Confirmar resultado del escaneo de credenciales
// ===========================================
+!cred_conf(Resultado)[source(AG)] <-
    if (Resultado == true) {
        .ev_log("Prueba de credenciales por defecto finalizada. Hallazgos, si los hay, en credentials.json")
    } else {
        .ev_log("No se pudo completar la prueba de credenciales")
    };
    .ev_goal_end("credenciales", Resultado);
    .print("===========================================");
    if (Resultado == true) {
        .ev_handoff(agInitialAccess, start_access);
        .send(agInitialAccess, achieve, start_access)
    }.

// ===========================================
// BELIEFS: Resultado crudo reportado por credAgR
// ===========================================
+cred_scan_completado(Resultado)[source(AG)] <-
    .ev_belief(cred_scan_completado, Resultado, AG).
