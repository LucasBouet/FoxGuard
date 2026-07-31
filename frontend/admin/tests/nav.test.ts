/**
 * The navigation model.
 *
 * There is no DOM here and no React. What is tested is the part that decides
 * which menu is highlighted and where a key press lands -- the part that would
 * otherwise only be checked by clicking around, and only on the paths someone
 * thought to click.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { KILL_SWITCH, NAV_ENTRIES, currentEntry, isCurrent, moveFocus } from "../src/lib/nav";

test("every entry has a route and no route is listed twice", () => {
  const hrefs: string[] = [];
  for (const entry of NAV_ENTRIES) {
    if (entry.kind === "link") hrefs.push(entry.href);
    else {
      assert.ok(entry.items.length > 0, `group ${entry.label} is empty`);
      for (const item of entry.items) {
        hrefs.push(item.href);
        assert.ok(item.hint.length > 0, `${item.href} has no hint`);
      }
    }
  }
  hrefs.push(KILL_SWITCH.href);
  assert.deepEqual(hrefs, [...new Set(hrefs)], "a route appears in two places");
  for (const href of hrefs) assert.match(href, /^\/[a-z-]*$/, href);
});

test("the overview is current only on the overview", () => {
  // The bug this exists to prevent: "/" is a prefix of every path, so a naive
  // startsWith would light up Overview on every page in the dashboard.
  assert.equal(isCurrent("/", "/"), true);
  assert.equal(isCurrent("/peers", "/"), false);
  assert.equal(isCurrent("/peers/abc", "/"), false);
});

test("a detail page keeps its section current", () => {
  assert.equal(isCurrent("/peers", "/peers"), true);
  assert.equal(isCurrent("/peers/6f1b7c1e", "/peers"), true);
  assert.equal(isCurrent("/peers?state=active", "/peers"), true);
  assert.equal(isCurrent("/peers/", "/peers"), true);
});

test("a route is not current for a section it merely starts with", () => {
  // /config must not make /configuration current, nor the other way round.
  assert.equal(isCurrent("/configuration", "/config"), false);
  assert.equal(isCurrent("/dns-records", "/dns"), false);
});

test("the group holding the current page is the current entry", () => {
  const devices = NAV_ENTRIES.findIndex((e) => e.kind === "group" && e.label === "Devices");
  assert.equal(currentEntry("/zones"), devices);
  assert.equal(currentEntry("/config"), devices);
  assert.equal(currentEntry("/peers/abc"), devices);
  assert.equal(currentEntry("/"), 0);
  assert.equal(currentEntry("/kill-switch"), -1, "the kill switch is deliberately outside");
  assert.equal(currentEntry("/login"), -1);
});

test("arrow keys wrap at both ends", () => {
  assert.equal(moveFocus(0, "ArrowDown", 3), 1);
  assert.equal(moveFocus(2, "ArrowDown", 3), 0);
  assert.equal(moveFocus(0, "ArrowUp", 3), 2);
  assert.equal(moveFocus(1, "ArrowUp", 3), 0);
  assert.equal(moveFocus(1, "Home", 3), 0);
  assert.equal(moveFocus(1, "End", 3), 2);
});

test("keys that do not move focus leave it alone", () => {
  // The component compares before and after to decide whether to swallow the
  // key; returning something different for Tab would trap focus in the menu.
  for (const key of ["Tab", "a", "Enter", "ArrowLeft", "PageDown"]) {
    assert.equal(moveFocus(1, key, 3), 1, key);
  }
});

test("an empty menu has no focus to move", () => {
  assert.equal(moveFocus(0, "ArrowDown", 0), -1);
});
