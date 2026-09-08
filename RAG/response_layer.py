import logging
from typing import Any, Dict, List, Optional
from . import config
from .incident_registry import IncidentRegistry
from .logging_agent import logging_agent

logger = logging.getLogger(__name__)


class ResponseLayer:
    """RESPONSE LAYER: executes validated actions, either automatically or by
    handing them off to a SOC analyst, via the XDR/EDR API."""

    def __init__(self, registry: Optional[IncidentRegistry] = None):
        self.registry = registry or IncidentRegistry()

    def _execute_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        # Placeholder for the real XDR/EDR API call. Actions requiring human approval are only queued.
        if action.get("requires_human_approval"):
            return {**action, "outcome": "queued_for_analyst"}
        return {**action, "outcome": "executed"}

    def execute(self, incident_id: int, approved_actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        with logging_agent.track("response_layer", "execute", incident_id=incident_id):
            results = [self._execute_action(action) for action in approved_actions]

            self.registry.log_action(
                incident_id,
                agent="response_layer",
                action="executed_actions",
                details={"results": results},
            )
            return {"results": results}
