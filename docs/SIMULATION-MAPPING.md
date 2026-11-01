# SIMULATION-MAPPING — Pre-Field Kit → PrintDoctor engines

Source ZIP: `MyPC_PrintDoctor_PreField_Simulation_20261101`  
SHA256: `57a40c225c30609a225a20ae0eaf1fe263e91543648fa947e72fa1be54dcb4a9`  
Fixtures path: `tests/Simulation/fixtures/`

| Suite | Count | Engine | Test |
|-------|-------|--------|------|
| `scenarios.json` | 48 | DecisionEngine + NetworkRootCauseEngine | `P21_Simulation_DiagnosticScenarios_RunOnRealEngines` |
| `office_5pc_scenarios.json` | 12 | CompareEngine | `P21_Simulation_Office5pc_CompareEngine` |
| `repair_scenarios.json` | 28 | RepairExecutor / OwnedFirewall | `P21_Simulation_RepairFaultInjection_28_OnRepairExecutor` |

Mapper: `src/MyPC.LanPrintDoctor.Core/Simulation/SimulationScenarioMapper.cs`  
Unmappable witness scenarios (WFP/pktmon) marked **BLOCKED**, never fake PASS.
