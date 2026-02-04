// ================================================================================================
// Agente: agDiscovery.asl
// Version: 2.0.0
//
// Descripción: Agente BDI coordinador de reconocimiento.
//   Orquesta las fases de descubrimiento delegando tareas al agente networkAgR.
//
// Flujo de ejecución:
//   1. start -> Solicita identificación de ubicación (whoami)
//   2. ip(IP) -> Recibe IP y solicita escaneo de red
//   3. conf(Resultado) -> Confirma escaneo y solicita detección de OS
//   4. os_completado -> Puede continuar con escaneo de servicios
// ================================================================================================

// Beliefs iniciales
fase(reconocimiento).

// ===========================================
// GOAL INICIAL: Comenzar reconocimiento
// ===========================================
!start.

+!start <-
    .print("===========================================");
    .print("[agDiscovery] Iniciando fase de reconocimiento");
    .print("[agDiscovery] Solicitando ubicación en la red...");
    .send(networkAgR, achieve, who(whoami)).

// ===========================================
// PLAN: Recibir IP y continuar con escaneo
// ===========================================
+!ip(IP)[source(AG)] <-
    .print("[agDiscovery] Ubicación recibida de", AG);
    .print("[agDiscovery] IP del agente:", IP);
    .print("[agDiscovery] Iniciando descubrimiento de red...");
    .send(networkAgR, achieve, net(IP)).

// ===========================================
// PLAN: Confirmar escaneo y continuar
// ===========================================
+!conf(Resultado)[source(AG)] <-
    .print("[agDiscovery] Escaneo de red completado por", AG);
    if (Resultado == true) {
        .print("[agDiscovery] Hosts descubiertos. Iniciando detección de OS...");
        .send(networkAgR, achieve, os_detection(true))
    } else {
        .print("[agDiscovery] No se encontraron hosts activos")
    }.

// ===========================================
// BELIEFS: Resultados de escaneos
// ===========================================
+scan_completado(Resultado)[source(AG)] <-
    .print("[agDiscovery] Belief: Escaneo de red =", Resultado).

+services_completado(Resultado)[source(AG)] <-
    .print("[agDiscovery] Belief: Escaneo de servicios =", Resultado).

+os_completado(Resultado)[source(AG)] <-
    .print("[agDiscovery] Belief: Detección de OS =", Resultado);
    if (Resultado == true) {
        .print("[agDiscovery] Reconocimiento básico completado");
        .print("[agDiscovery] Iniciando escaneo de servicios...");
        .send(networkAgR, achieve, service_scan("all"))
    };
    .print("===========================================");
    .print("[agDiscovery] Fase de reconocimiento finalizada");
    .print("===========================================").
