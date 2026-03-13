"""Tests for the Warden hooks module."""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from warden.hooks import _is_pre_action, should_block


class TestIsPreAction(unittest.TestCase):
    """Test pre-action event name detection across all agents."""

    # Claude Code events
    def test_claude_pre_tool_use(self):
        self.assertTrue(_is_pre_action("PreToolUse"))

    def test_claude_user_prompt_submit(self):
        self.assertTrue(_is_pre_action("UserPromptSubmit"))

    def test_claude_post_tool_use(self):
        self.assertFalse(_is_pre_action("PostToolUse"))

    def test_claude_stop(self):
        self.assertFalse(_is_pre_action("Stop"))

    # Cursor events
    def test_cursor_before_shell_command(self):
        self.assertTrue(_is_pre_action("beforeShellCommand"))

    def test_cursor_before_submit_prompt(self):
        self.assertTrue(_is_pre_action("beforeSubmitPrompt"))

    def test_cursor_before_file_write(self):
        self.assertTrue(_is_pre_action("beforeFileWrite"))

    def test_cursor_after_shell_command(self):
        self.assertFalse(_is_pre_action("afterShellCommand"))

    def test_cursor_after_file_write(self):
        self.assertFalse(_is_pre_action("afterFileWrite"))

    # Windsurf events
    def test_windsurf_pre_run_command(self):
        self.assertTrue(_is_pre_action("pre_run_command"))

    def test_windsurf_pre_write_code(self):
        self.assertTrue(_is_pre_action("pre_write_code"))

    def test_windsurf_pre_user_prompt(self):
        self.assertTrue(_is_pre_action("pre_user_prompt"))

    def test_windsurf_post_run_command(self):
        self.assertFalse(_is_pre_action("post_run_command"))

    def test_windsurf_post_cascade_response(self):
        self.assertFalse(_is_pre_action("post_cascade_response"))

    # Edge cases
    def test_empty_string(self):
        self.assertFalse(_is_pre_action(""))

    def test_unknown_event(self):
        self.assertFalse(_is_pre_action("somethingElse"))


class TestShouldBlock(unittest.TestCase):
    """Test the blocking decision logic."""

    def test_blocks_destructive_on_pre_action(self):
        findings = [{"category": "destructive_command", "severity": "CRITICAL"}]
        event = {"agent_event": "PreToolUse", "type": "shell"}
        self.assertIsNotNone(should_block(findings, event))

    def test_blocks_secret_exfil_on_pre_action(self):
        findings = [{"category": "secret_exfiltration", "severity": "CRITICAL"}]
        event = {"agent_event": "beforeShellCommand", "type": "shell"}
        self.assertIsNotNone(should_block(findings, event))

    def test_no_block_on_post_action(self):
        findings = [{"category": "destructive_command", "severity": "CRITICAL"}]
        event = {"agent_event": "PostToolUse", "type": "shell"}
        self.assertIsNone(should_block(findings, event))

    def test_no_block_on_empty_findings(self):
        event = {"agent_event": "PreToolUse", "type": "shell"}
        self.assertIsNone(should_block([], event))

    def test_no_block_on_low_severity_category(self):
        findings = [{"category": "risky_write", "severity": "MEDIUM"}]
        event = {"agent_event": "PreToolUse", "type": "file_write"}
        self.assertIsNone(should_block(findings, event))

    def test_file_read_only_blocked_for_secret_access(self):
        findings = [{"category": "destructive_command", "severity": "CRITICAL"}]
        event = {"agent_event": "PreToolUse", "type": "file_read"}
        self.assertIsNone(should_block(findings, event))

        findings = [{"category": "secret_access", "severity": "HIGH"}]
        event = {"agent_event": "PreToolUse", "type": "file_read"}
        self.assertIsNotNone(should_block(findings, event))


if __name__ == "__main__":
    unittest.main()
