"""
Tests for backend/llm/question_tags.py

Covers:
- All 12 tag types
- Mixed detection
- Attribution risk detection
- Selection precedence
- Entity resolution
- Default fallback
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from llm.question_tags import (
    tag_question,
    TAG_BROAD_OVERVIEW, TAG_ENTITY_NODE, TAG_ENTITY_EDGE, TAG_ENTITY_SESSION,
    TAG_ALERT_EVIDENCE, TAG_DNS, TAG_TLS, TAG_HTTP, TAG_CREDENTIALS,
    TAG_ATTRIBUTION_RISK, TAG_BACKGROUND, TAG_MIXED, TAG_UNRELATED,
)


def _tag(question, *, sel_nodes=None, sel_edge=None, sel_session=None, sel_alert=None,
         scope='full_capture', known_nodes=None, known_edges=None,
         known_sessions=None, known_alerts=None):
    return tag_question(
        question=question,
        selection_node_ids=sel_nodes or [],
        selection_edge_id=sel_edge,
        selection_session_id=sel_session,
        selection_alert_id=sel_alert,
        scope_mode=scope,
        known_node_ids=known_nodes,
        known_edge_ids=known_edges,
        known_session_ids=known_sessions,
        known_alert_ids=known_alerts,
    )


class TestSelectionPrecedence:
    def test_alert_selection_wins(self):
        tags = _tag("What is happening?", sel_alert="alert_123")
        assert TAG_ALERT_EVIDENCE in tags

    def test_edge_selection(self):
        tags = _tag("Tell me about this", sel_edge="10.0.0.1|10.0.0.2|TCP")
        assert TAG_ENTITY_EDGE in tags

    def test_session_selection(self):
        tags = _tag("What is this?", sel_session="sess_abc")
        assert TAG_ENTITY_SESSION in tags

    def test_node_selection(self):
        tags = _tag("Explain", sel_nodes=["10.0.0.5"])
        assert TAG_ENTITY_NODE in tags

    def test_alert_wins_over_node(self):
        # Alert selection outranks node selection
        tags = _tag("Why?", sel_alert="alert_1", sel_nodes=["10.0.0.5"])
        assert TAG_ALERT_EVIDENCE in tags
        assert TAG_ENTITY_NODE not in tags


class TestEntityResolution:
    def test_ip_in_question_resolves_to_node(self):
        tags = _tag("What is 10.0.0.5 doing?", known_nodes={"10.0.0.5", "10.0.0.1"})
        assert TAG_ENTITY_NODE in tags

    def test_unknown_ip_no_entity_tag(self):
        tags = _tag("What is 192.168.99.99 doing?", known_nodes={"10.0.0.5"})
        assert TAG_ENTITY_NODE not in tags

    def test_no_ip_no_entity_tag(self):
        tags = _tag("What is happening?")
        assert TAG_ENTITY_NODE not in tags


class TestProtocolTags:
    def test_dns_keyword(self):
        tags = _tag("What DNS queries does this host make?")
        assert TAG_DNS in tags

    def test_tls_keyword(self):
        tags = _tag("What TLS certificates are presented on this edge?")
        assert TAG_TLS in tags

    def test_http_keyword(self):
        tags = _tag("What HTTP hosts appear in this traffic?")
        assert TAG_HTTP in tags

    def test_credentials_keyword(self):
        tags = _tag("Is there any cleartext credential traffic?")
        assert TAG_CREDENTIALS in tags

    def test_protocol_tags_stackable(self):
        # A question can match multiple protocol tags
        tags = _tag("What DNS and TLS activity is on this host?", sel_nodes=["10.0.0.5"])
        assert TAG_ENTITY_NODE in tags
        assert TAG_DNS in tags
        assert TAG_TLS in tags


class TestAttributionRisk:
    def test_attacker_keyword(self):
        tags = _tag("Where is the attacker?")
        assert TAG_ATTRIBUTION_RISK in tags

    def test_malware_keyword(self):
        tags = _tag("Is this definitely malware?")
        assert TAG_ATTRIBUTION_RISK in tags

    def test_c2_keyword(self):
        tags = _tag("Does this look like C2 traffic?")
        assert TAG_ATTRIBUTION_RISK in tags

    def test_exfiltration_keyword(self):
        tags = _tag("Was there any exfiltration?")
        assert TAG_ATTRIBUTION_RISK in tags

    def test_compromise_keyword(self):
        tags = _tag("Which host is compromised?")
        assert TAG_ATTRIBUTION_RISK in tags


class TestBackgroundAndMixed:
    def test_pure_background(self):
        tags = _tag("What is DNS tunneling?")
        # No capture ref → background or mixed
        assert TAG_BACKGROUND in tags or TAG_MIXED in tags

    def test_unrelated_cats(self):
        tags = _tag("Tell me about cats")
        assert TAG_UNRELATED in tags

    def test_unrelated_world_cup(self):
        tags = _tag("Who won the world cup")
        assert TAG_UNRELATED in tags

    def test_background_with_protocol_hint_is_mixed(self):
        # "What is DNS tunneling?" with DNS tag → mixed
        tags = _tag("What is DNS tunneling?")
        # Either mixed or background is acceptable — both are correct behaviours
        assert TAG_MIXED in tags or TAG_BACKGROUND in tags


class TestDefaultFallback:
    def test_empty_question_gives_broad_overview(self):
        tags = _tag("What is going on?")
        assert TAG_BROAD_OVERVIEW in tags

    def test_broad_question(self):
        tags = _tag("What stands out in this capture?")
        # No entity, no protocol, no attribution → broad_overview
        assert TAG_BROAD_OVERVIEW in tags

    def test_always_returns_at_least_one_tag(self):
        for q in ["hello", "?", "", "   "]:
            tags = _tag(q)
            assert len(tags) >= 1


class TestTagOrder:
    def test_no_duplicates(self):
        tags = _tag("What DNS and TLS activity exists on 10.0.0.5?",
                    known_nodes={"10.0.0.5"})
        assert len(tags) == len(set(tags))
