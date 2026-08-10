// ================================================================================================
// Agente: credAgR.asl
// Version: 1.0.0
//
// Descripción: Agente reactivo de acceso por credenciales. Prueba credenciales
//   por defecto contra los servicios HTTP/SSH que networkAgR ya descubrió
//   (services.json); no escanea nada nuevo. MITRE ATT&CK: T1110 Brute Force.
//
// Cada credencial válida encontrada se reporta en tiempo real como hallazgo
// (ver events.finding() en credAgR.py); este agente no delibera, solo ejecuta
// lo que el agente BDI (agCredAccess) le pide.
// ================================================================================================

+!cred_scan(Target)[source(AG)] <-
    .ev_action_start(cred_scan, AG, Target);
    .cred_scan(Target, Resultado);
    .ev_action_result(cred_scan, Resultado, "");
    .send(AG, tell, cred_scan_completado(Resultado));
    .send(AG, achieve, cred_conf(Resultado)).
