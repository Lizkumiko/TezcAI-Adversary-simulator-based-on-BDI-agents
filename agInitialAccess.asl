// ================================================================================================
// Agente: agInitialAccess.asl
// Version: 1.0.0
//
// Descripción: Agente BDI de acceso inicial.
//   MITRE ATT&CK: TA0001 Initial Access (T1078 Valid Accounts).
//   Recibe el handoff de agCredAccess y delega en initAgR la verificación de
//   acceso real usando las credenciales válidas encontradas (credentials.json).
//   No prueba credenciales nuevas ni escanea nada: solo confirma pie de apoyo.
//
// Flujo de ejecución:
//   1. start_access[source(agCredAccess)] -> Delega en initAgR la verificación de acceso
//   2. access_conf(Resultado) -> Recibe confirmación y cierra la fase
// ================================================================================================

fase(acceso_inicial).

// ===========================================
// GOAL: Iniciar fase de acceso inicial
// Trigger: handoff de agCredAccess al finalizar la prueba de credenciales
// ===========================================
+!start_access[source(agCredAccess)] <-
    .print("===========================================");
    .ev_phase("acceso_inicial");
    .ev_goal_start("start_access");
    .ev_delegation(initAgR, initial_access);
    .send(initAgR, achieve, initial_access("all")).

// ===========================================
// PLAN: Confirmar resultado del intento de acceso inicial
// ===========================================
+!access_conf(Resultado)[source(AG)] <-
    if (Resultado == true) {
        .ev_log("Verificación de acceso inicial finalizada. Accesos confirmados, si los hay, en access.json")
    } else {
        .ev_log("No se pudo completar la verificación de acceso inicial")
    };
    .ev_goal_end("acceso_inicial", Resultado);
    .print("===========================================").

// ===========================================
// BELIEF: Resultado crudo reportado por initAgR
// ===========================================
+initial_access_completado(Resultado)[source(AG)] <-
    .ev_belief(initial_access_completado, Resultado, AG).
