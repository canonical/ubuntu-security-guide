#!/usr/bin/python3
#
# Ubuntu Security Guide
# Copyright (C) 2025 Canonical Limited
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
from dataclasses import dataclass
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


@dataclass
class Control:
    control_id: str
    title: str


@dataclass
class Variable:
    name: str
    value: str
    control: Control


@dataclass
class Rule:
    name: str
    selected: bool
    control: Control


class CaCParsingException(Exception):
    pass


class CaCProfile:
    def __init__(self):
        self.controls = {}
        self.vars = {}
        self.rules = {}

    def _add_or_update_rule(self, rule_name, selected, control):
        # create rule object and add to list of rules if it doesn't exist
        if rule_name not in self.rules:
            rule = Rule(rule_name, selected, control)
            self.rules[rule_name] = rule
            return rule
        if selected != self.rules[rule_name].selected:
            # disable or enable existing rule
            logger.info(
                f"Overriding rule selection to '{rule_name}={selected}' "
                f"in control '{control.control_id}'"
            )
            self.rules[rule_name].selected = selected
        else:
            # ignore duplicate rules
            logger.debug(
                f"Ignoring duplicate rule '{rule_name}' in "
                f"control '{control.control_id}'"
            )
        return None

    def _add_or_update_variable(self, var_name, var_value, control):
        # create variable object and add to list of vars if it doesn't exist
        # if it exists, update the value
        if var_name not in self.vars:
            var = Variable(var_name, var_value, control)
            self.vars[var_name] = var
            return var
        if var_value != self.vars[var_name].value:
            # override
            logger.info(
                f"Overriding variable '{var_name}={var_value}' "
                f"in control '{control.control_id}'"
            )
            self.vars[var_name].value = var_value
        else:
            # ignore duplicate rules
            logger.debug(
                f"Ignoring duplicate variable '{var_name}={var_value}' "
                f"in control '{control.control_id}'"
            )
        return None

    def _add_control(self, control_id, title):
        # add control to list of controls in profile
        # if it exists, fail
        if control_id not in self.controls:
            control = Control(control_id, title)
            self.controls[control_id] = control
            return control
        raise CaCParsingException(
            f"Duplicate controls not supported(control id: '{control_id}')."
        )

    def _add_controls_from_file(self, controls_path, level_id):
        # parse control file and return items corresponding to level
        with open(controls_path) as file:
            yaml_data = yaml.safe_load(file)

        # Levels can be inherited e.g. level2 can match
        # both `level2` and `level1` rules.
        # Map level inheritance recursively.
        # special level keyword 'all' matches all levels.
        applicable_levels = set()

        def _parse_level(level_id):
            levels = [
                level
                for level in yaml_data.get("levels", {})
                if level.get("id") == level_id or level_id == "all"
            ]
            for level in levels:
                applicable_levels.add(level["id"])
                for parent_level_id in level.get("inherits_from", []):
                    if parent_level_id not in applicable_levels:
                        _parse_level(parent_level_id)

        _parse_level(level_id)

        for control_data in yaml_data.get("controls", {}):
            control_levels = set(control_data.get("levels", []))
            if not control_levels & applicable_levels:
                # control is not applicable to selected level
                continue

            control = self._add_control(
                    str(control_data["id"]),
                    str(control_data["title"])
                    )

            for rule in control_data.get("rules", []):
                if "=" in rule:
                    name, value = rule.split("=")
                    self._add_or_update_variable(name, value, control)
                elif rule.startswith("!"):
                    self._add_or_update_rule(rule.strip("!"), False, control)
                else:
                    self._add_or_update_rule(rule, True, control)

    @staticmethod
    def from_yaml(yaml_path):
        # generate profile object from profile yaml file

        with open(yaml_path) as file:
            profile_data = yaml.safe_load(file)

        profile = CaCProfile()

        # this control is for all rules and vars that are defined in the profile
        # and don't belong to any specific control
        profile_control = profile._add_control(
            "_Profile_Rules_And_Variables_",
            "Profile rules and variables not belonging to a specific control",
        )

        for selection in profile_data.get("selections", []):

            # variables
            if "=" in selection:
                var_name, var_value = selection.split("=")
                profile._add_or_update_variable(var_name, var_value, profile_control)

            # disabled rules
            elif selection.startswith("!"):
                profile._add_or_update_rule(
                    selection.strip("!"), False, profile_control
                )

            # controls
            elif ":" in selection:
                tags = selection.split(":")
                controls_tag = tags[0]
                if len(tags) == 3:
                    level = tags[2]
                else:
                    level = "all"

                controls_dir = Path(yaml_path).parents[3] / "controls"
                controls_path = controls_dir / f"{controls_tag}.yml"
                profile._add_controls_from_file(controls_path, level)



            # additional uncategorized rules
            else:
                profile._add_or_update_rule(selection, True, profile_control)

        return profile
