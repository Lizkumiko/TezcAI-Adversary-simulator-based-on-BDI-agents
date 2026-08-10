// ================================================================================================
// Agente: initAgR.asl
// Version: 1.0.0
//
// Descripción: Agente reactivo de acceso inicial. Confirma acceso real con las
//   credenciales válidas que credAgR ya encontró (credentials.json); no prueba
//   credenciales nuevas ni escanea nada. MITRE ATT&CK: T1078 Valid Accounts.
//
// Cada acceso confirmado se reporta en tiempo real como hallazgo (ver
// events.finding() en initAgR.py); este agente no delibera, solo ejecuta lo
// que el agente BDI (agInitialAccess) le pide.
// ================================================================================================

+!initial_access(Target)[source(AG)] <-
    .ev_action_start(initial_access, AG, Target);
    .initial_access(Target, Resultado);
    .ev_action_result(initial_access, Resultado, "");
    .send(AG, tell, initial_access_completado(Resultado));
    .send(AG, achieve, access_conf(Resultado)).
