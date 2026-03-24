//! The sparse graph store: add/get/remove nodes, edges, flows.

use std::collections::HashMap;
use crate::entity::{Edge, Flow, Node};
use crate::types::{EntityId, FlowId};

/// In-memory sparse graph. No persistence yet — that's a later stage.
#[derive(Debug, Default)]
pub struct Graph {
    pub nodes: HashMap<EntityId, Node>,
    pub edges: HashMap<EntityId, Edge>,
    pub flows: HashMap<FlowId, Flow>,
    /// Adjacency: node_id → set of edge_ids that touch it.
    pub adjacency: HashMap<EntityId, Vec<EntityId>>,
}

impl Graph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, node: Node) {
        let id = node.id;
        self.nodes.insert(id, node);
        self.adjacency.entry(id).or_default();
    }

    pub fn add_edge(&mut self, edge: Edge) {
        let eid = edge.id;
        self.adjacency.entry(edge.source).or_default().push(eid);
        if !edge.directed {
            self.adjacency.entry(edge.target).or_default().push(eid);
        }
        self.edges.insert(eid, edge);
    }

    pub fn add_flow(&mut self, flow: Flow) {
        self.flows.insert(flow.id, flow);
    }

    pub fn neighbors(&self, node_id: &EntityId) -> Vec<EntityId> {
        let Some(edge_ids) = self.adjacency.get(node_id) else {
            return Vec::new();
        };
        edge_ids
            .iter()
            .filter_map(|eid| self.edges.get(eid))
            .map(|e| {
                if e.source == *node_id {
                    e.target
                } else {
                    e.source
                }
            })
            .collect()
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }
}
