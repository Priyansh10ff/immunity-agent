"""Prismor Warden cloaking plugin for Hermes Agent (filesystem install).

When installed via ``immunity cloak install --agent hermes``, this
directory is copied to ``~/.hermes/plugins/prismor-warden-cloak/``.
Hermes' filesystem scanner picks up ``plugin.yaml`` and calls
``register()`` from this module, which delegates to the shared
implementation in ``warden.cloaking.hermes_plugin_entry``.

When immunity-agent is pip-installed, Hermes discovers the same
``register()`` via the ``hermes_agent.plugins`` entry-point group
(defined in ``pyproject.toml``), pointing directly to the shared module.
"""

from warden.cloaking.hermes_plugin_entry import register

__all__ = ["register"]
