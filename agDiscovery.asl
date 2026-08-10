// ================================================================================================
// Agente: agDiscovery.asl
// Version: 2.0.0
//
// Descripción: Agente BDI coordinador de reconocimiento.
//   Orquesta las fases de descubrimiento delegando tareas al agente networkAgR.
//   Cada paso relevante se reporta con .ev_* (consola + evento JSON por WebSocket);
//   este agente no conoce ese detalle, solo invoca acciones semánticas.
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
    .ev_phase("reconocimiento");
    .ev_goal_start("start");
    .ev_delegation(networkAgR, whoami);
    .send(networkAgR, achieve, who(whoami)).

// ===========================================
// PLAN: Recibir IP y continuar con escaneo
// ===========================================
+!ip(IP)[source(AG)] <-
    .ev_belief(ip, IP, AG);
    .ev_goal_start("ip");
    .ev_delegation(networkAgR, network_scanning);
    .send(networkAgR, achieve, net(IP)).

// ===========================================
// PLAN: Confirmar escaneo y continuar
// ===========================================
+!conf(Resultado)[source(AG)] <-
    .ev_goal_start("conf");
    if (Resultado == true) {
        .ev_delegation(networkAgR, os_detection);
        .send(networkAgR, achieve, os_detection(true))
    } else {
        .ev_log("No se encontraron hosts activos")
    }.

// ===========================================
// BELIEFS: Resultados de escaneos
// ===========================================
+scan_completado(Resultado)[source(AG)] <-
    .ev_belief(scan_completado, Resultado, AG).

+os_completado(Resultado)[source(AG)] <-
    .ev_belief(os_completado, Resultado, AG);
    if (Resultado == true) {
        .ev_delegation(networkAgR, service_scanning);
        .send(networkAgR, achieve, service_scan("all"))
    }.

// ===========================================
// BELIEF: Escaneo de servicios completado -> fin del reconocimiento.
// Entrega la fase al siguiente agente BDI del kill chain (acceso por credenciales).
// ===========================================
+services_completado(Resultado)[source(AG)] <-
    .ev_belief(services_completado, Resultado, AG);
    .ev_goal_end("reconocimiento", Resultado);
    .print("===========================================");
    if (Resultado == true) {
        .ev_handoff(agCredAccess, start_cred);
        .send(agCredAccess, achieve, start_cred)
    }.
