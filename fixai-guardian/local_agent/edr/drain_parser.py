"""
FixAI EDR — Drain Online Log Parsing Algorithm
==============================================

Implements the Drain log parsing algorithm using a fixed-depth parse tree
to extract structured templates and dynamic parameters from unstructured
event and security log streams in real-time.

Mathematical & Algorithmic Principles:
  1. Fixed-Depth Tree Search:
     - Root -> Log Message Length -> First Token (Header) -> Similarity Search -> Template Node.
  2. Dynamic Variable Masking:
     - IP addresses, GUIDs/UUIDs, hex memory addresses, timestamps, process IDs,
       and numeric tokens are tokenized into '<*>' placeholders.
  3. Template Matching via Token Similarity:
     - Calculates token overlap ratio between incoming log message and cluster templates.
     - If similarity >= sim_threshold (default: 0.5), merge into template.
     - Else create new template cluster.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple


class Node:
    """Parse tree internal node."""

    def __init__(self, depth: int = 1, digit_or_token: Optional[str] = None):
        self.depth = depth
        self.digit_or_token = digit_or_token
        self.children: Dict[str, Any] = {}
        self.clusters: List[LogCluster] = []


class LogCluster:
    """Represents a discovered log template cluster."""

    def __init__(self, log_template: List[str], log_id: int):
        self.log_template = log_template
        self.log_id = log_id
        self.size = 1

    def get_template(self) -> str:
        return " ".join(self.log_template)

    def __repr__(self) -> str:
        return f"<LogCluster ID={self.log_id} size={self.size} template='{self.get_template()}'>"


class DrainParser:
    """
    Real-time streaming Drain log parser.
    Transforms heterogeneous, unstructured OS logs into structured event templates.
    """

    def __init__(
        self,
        depth: int = 4,
        sim_threshold: float = 0.5,
        max_children: int = 100,
    ):
        """
        Args:
            depth: Max depth of parse tree (default: 4).
            sim_threshold: Minimum similarity threshold for cluster matching.
            max_children: Max branch factor per internal node.
        """
        self.depth = depth - 2  # subtract root and cluster layer
        self.sim_threshold = sim_threshold
        self.max_children = max_children
        self.root = Node(depth=0)
        self.clusters: List[LogCluster] = []
        self._cluster_counter = 0

        # Regex patterns for dynamic variable substitution
        self._patterns = [
            (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<IP>"),
            (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<HEX>"),
            (re.compile(r"\b[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b"), "<GUID>"),
            (re.compile(r"\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(\.\d+)?Z?\b"), "<TIMESTAMP>"),
            (re.compile(r"\b\d+\b"), "<NUM>"),
        ]

    def _preprocess(self, message: str) -> List[str]:
        """Normalize and substitute dynamic variables with generic tokens."""
        content = message.strip()
        for pattern, replacement in self._patterns:
            content = pattern.sub(replacement, content)
        # Tokenize by whitespace
        return content.split()

    def _seq_distance(self, seq1: List[str], seq2: List[str]) -> Tuple[float, int]:
        """Compute token similarity ratio between two token sequences."""
        if len(seq1) != len(seq2):
            return 0.0, 0

        sim_tokens = 0
        num_of_vars = 0

        for token1, token2 in zip(seq1, seq2):
            if token1 == "<*>":
                num_of_vars += 1
                continue
            if token1 == token2:
                sim_tokens += 1

        ret_val = float(sim_tokens) / len(seq1)
        return ret_val, num_of_vars

    def _fast_match(self, cluster_list: List[LogCluster], tokens: List[str]) -> Optional[LogCluster]:
        """Find the best matching template cluster from candidates."""
        max_sim = -1.0
        max_num_of_vars = -1
        max_cluster: Optional[LogCluster] = None

        for cluster in cluster_list:
            cur_sim, cur_num_of_vars = self._seq_distance(cluster.log_template, tokens)
            if cur_sim > max_sim or (cur_sim == max_sim and cur_num_of_vars > max_num_of_vars):
                max_sim = cur_sim
                max_num_of_vars = cur_num_of_vars
                max_cluster = cluster

        if max_sim >= self.sim_threshold:
            return max_cluster
        return None

    def parse(self, message: str) -> Dict[str, Any]:
        """
        Ingest a raw log message, assign/create a template cluster,
        and extract template and dynamic parameters.

        Returns:
            Dict containing template_id, template, variables, and raw message.
        """
        tokens = self._preprocess(message)
        if not tokens:
            return {
                "cluster_id": 0,
                "template": "",
                "variables": [],
                "raw": message,
            }

        seq_len = len(tokens)
        curr_node = self.root

        # Layer 1: Message length
        seq_len_str = str(seq_len)
        if seq_len_str not in curr_node.children:
            new_node = Node(depth=1, digit_or_token=seq_len_str)
            curr_node.children[seq_len_str] = new_node
            curr_node = new_node
        else:
            curr_node = curr_node.children[seq_len_str]

        # Layer 2 to depth: Token path traversal
        for i in range(min(self.depth, seq_len)):
            token = tokens[i]
            # Replace numeric/masked tokens with wildcard branch
            if any(char.isdigit() for char in token) or "<" in token:
                token = "<*>"

            if token not in curr_node.children:
                if len(curr_node.children) < self.max_children:
                    new_node = Node(depth=curr_node.depth + 1, digit_or_token=token)
                    curr_node.children[token] = new_node
                    curr_node = new_node
                else:
                    if "<*>" not in curr_node.children:
                        new_node = Node(depth=curr_node.depth + 1, digit_or_token="<*>")
                        curr_node.children["<*>"] = new_node
                        curr_node = new_node
                    else:
                        curr_node = curr_node.children["<*>"]
            else:
                curr_node = curr_node.children[token]

        # Cluster layer: Match or create cluster
        match_cluster = self._fast_match(curr_node.clusters, tokens)

        if match_cluster is None:
            self._cluster_counter += 1
            new_cluster = LogCluster(log_template=list(tokens), log_id=self._cluster_counter)
            curr_node.clusters.append(new_cluster)
            self.clusters.append(new_cluster)
            target_cluster = new_cluster
        else:
            # Update template dynamically: replace non-identical tokens with <*>
            updated_template: List[str] = []
            for t1, t2 in zip(match_cluster.log_template, tokens):
                if t1 == t2:
                    updated_template.append(t1)
                else:
                    updated_template.append("<*>")
            match_cluster.log_template = updated_template
            match_cluster.size += 1
            target_cluster = match_cluster

        # Extract dynamic variable parameters
        variables: List[str] = []
        for t_orig, t_tmpl in zip(tokens, target_cluster.log_template):
            if t_tmpl == "<*>":
                variables.append(t_orig)

        return {
            "cluster_id": target_cluster.log_id,
            "template": target_cluster.get_template(),
            "variables": variables,
            "cluster_size": target_cluster.size,
            "raw": message,
        }
