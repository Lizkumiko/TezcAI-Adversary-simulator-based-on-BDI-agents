// ================================================================================================
// Agente: networkAgR.asl
// Version: 2.0.0
//
// Descripción: Agente reactivo de red. Ejecuta acciones de reconocimiento:
//   - Identificación de ubicación en la red (whoami)
//   - Descubrimiento de hosts activos (network_scanning)
//   - Escaneo de servicios (service_scanning)
//   - Detección de sistema operativo (os_detection)
//
// Cada acción reporta inicio/resultado con .ev_* (consola + evento JSON por
// WebSocket); este agente no conoce ese detalle, solo ejecuta lo que le piden.
// ================================================================================================

// Plan: Identificar ubicación en la red
// Trigger: Cuando agDiscovery solicita identificación
+!who(Msg)[source(agDiscovery)] <-
    .ev_action_start(whoami, agDiscovery, "");
    .whoami("Identificando posición del agente en la red", IP);
    .ev_action_result(whoami, true, IP);
    .send(agDiscovery, achieve, ip(IP)).

// Plan: Escanear red en busca de hosts activos
// Trigger: Cuando agDiscovery solicita escaneo con una IP base
+!net(IP)[source(AG)] <-
    .ev_action_start(network_scanning, AG, IP);
    .network_scanning(IP, Resultado);
    .ev_action_result(network_scanning, Resultado, "");
    .send(agDiscovery, tell, scan_completado(Resultado));
    .send(agDiscovery, achieve, conf(Resultado)).

// Plan: Escanear servicios en los targets descubiertos
// Trigger: Cuando agDiscovery solicita escaneo de servicios
+!service_scan(Target)[source(AG)] <-
    .ev_action_start(service_scanning, AG, Target);
    .service_scanning(Target, Resultado);
    .ev_action_result(service_scanning, Resultado, "");
    .send(agDiscovery, tell, services_completado(Resultado)).

// Plan: Detectar sistemas operativos
// Trigger: Cuando agDiscovery solicita detección de OS
+!os_detection(Proceder)[source(AG)] <-
    .ev_action_start(os_detection, AG, "");
    .os_detection(Proceder, Resultado);
    .ev_action_result(os_detection, Resultado, "");
    .send(agDiscovery, tell, os_completado(Resultado)).
