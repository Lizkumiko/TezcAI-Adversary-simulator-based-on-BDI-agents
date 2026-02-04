// ================================================================================================
// Agente: networkAgR.asl
// Version: 2.0.0
//
// Descripción: Agente reactivo de red. Ejecuta acciones de reconocimiento:
//   - Identificación de ubicación en la red (whoami)
//   - Descubrimiento de hosts activos (network_scanning)
//   - Escaneo de servicios (service_scanning)
//   - Detección de sistema operativo (os_detection)
// ================================================================================================

// Plan: Identificar ubicación en la red
// Trigger: Cuando agDiscovery solicita identificación
+!who(Msg)[source(agDiscovery)] <-
    .print("[networkAgR] Iniciando identificación de ubicación en la red");
    IP = .whoami("Identificando posición del agente en la red");
    .print("[networkAgR] IP detectada:", IP);
    .send(agDiscovery, achieve, ip(IP)).

// Plan: Escanear red en busca de hosts activos
// Trigger: Cuando agDiscovery solicita escaneo con una IP base
+!net(IP)[source(AG)] <-
    .print("[networkAgR] Iniciando descubrimiento de red desde:", IP);
    Resultado = .network_scanning(IP);
    .print("[networkAgR] Escaneo completado. Éxito:", Resultado);
    .send(agDiscovery, tell, scan_completado(Resultado));
    .send(agDiscovery, achieve, conf(Resultado)).

// Plan: Escanear servicios en los targets descubiertos
// Trigger: Cuando agDiscovery solicita escaneo de servicios
+!service_scan(Target)[source(AG)] <-
    .print("[networkAgR] Iniciando escaneo de servicios en:", Target);
    Resultado = .service_scanning(Target);
    .print("[networkAgR] Escaneo de servicios completado. Éxito:", Resultado);
    .send(agDiscovery, tell, services_completado(Resultado)).

// Plan: Detectar sistemas operativos
// Trigger: Cuando agDiscovery solicita detección de OS
+!os_detection(Proceder)[source(AG)] <-
    .print("[networkAgR] Iniciando detección de sistemas operativos");
    Resultado = .os_detection(Proceder);
    .print("[networkAgR] Detección de OS completada. Éxito:", Resultado);
    .send(agDiscovery, tell, os_completado(Resultado)).
