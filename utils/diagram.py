"""
Éditeur de diagrammes d'architecture
Module pour visualiser et documenter l'architecture AWS du client
"""

import streamlit as st
from streamlit_agraph import agraph, Node, Edge, Config
import json
from pathlib import Path


class DiagramEditor:
    def __init__(self):
        self.diagram_dir = Path("data/diagrams")
        self.diagram_dir.mkdir(parents=True, exist_ok=True)

        if 'nodes' not in st.session_state:
            st.session_state.nodes = []

        if 'edges' not in st.session_state:
            st.session_state.edges = []

    def render(self):
        """Render the diagram editor interface"""

        col1, col2 = st.columns([2, 1])

        with col1:
            st.subheader("Architecture Diagram")
            self._render_diagram()

        with col2:
            st.subheader("Add Components")
            self._render_controls()

        st.markdown("---")

        col1, col2, col3 = st.columns(3)

        with col1:
            if st.button("Save Diagram", use_container_width=True):
                self._save_diagram()
                st.success("Diagram saved!")

        with col2:
            if st.button("Load Diagram", use_container_width=True):
                self._load_diagram()
                st.success("Diagram loaded!")

        with col3:
            if st.button("Clear Diagram", use_container_width=True):
                st.session_state.nodes = []
                st.session_state.edges = []
                st.rerun()

    def _render_diagram(self):
        """Render the interactive diagram"""

        if not st.session_state.nodes:
            st.info("Add components using the panel on the right to build your architecture diagram.")
            return

        nodes = [
            Node(
                id=node['id'],
                label=node['label'],
                size=25,
                color=node.get('color', '#667eea'),
                shape=node.get('shape', 'box')
            )
            for node in st.session_state.nodes
        ]

        edges = [
            Edge(
                source=edge['source'],
                target=edge['target'],
                label=edge.get('label', ''),
                color=edge.get('color', '#999')
            )
            for edge in st.session_state.edges
        ]

        config = Config(
            width=700,
            height=500,
            directed=True,
            physics=True,
            hierarchical=False
        )

        agraph(nodes=nodes, edges=edges, config=config)

    def _render_controls(self):
        """Render diagram controls"""

        st.markdown("#### AWS Components")

        # Component templates
        components = {
            "VPC": {"color": "#FF9900", "shape": "box"},
            "EC2": {"color": "#FF9900", "shape": "ellipse"},
            "RDS": {"color": "#3B48CC", "shape": "database"},
            "S3": {"color": "#569A31", "shape": "box"},
            "Lambda": {"color": "#FF9900", "shape": "diamond"},
            "ALB": {"color": "#8C4FFF", "shape": "triangle"},
            "API Gateway": {"color": "#FF4F8B", "shape": "box"},
            "CloudFront": {"color": "#8C4FFF", "shape": "star"},
            "Route53": {"color": "#8C4FFF", "shape": "ellipse"},
            "Internet Gateway": {"color": "#FF9900", "shape": "box"},
            "NAT Gateway": {"color": "#FF9900", "shape": "box"},
            "Security Group": {"color": "#DD344C", "shape": "box"},
        }

        component_type = st.selectbox("Select Component", list(components.keys()))

        component_name = st.text_input("Component Name", value=component_type)

        if st.button("Add Component", use_container_width=True):
            node_id = f"node_{len(st.session_state.nodes)}"
            st.session_state.nodes.append({
                'id': node_id,
                'label': component_name,
                'color': components[component_type]['color'],
                'shape': components[component_type]['shape']
            })
            st.rerun()

        st.markdown("---")
        st.markdown("#### Connections")

        if len(st.session_state.nodes) >= 2:
            node_options = [f"{n['label']} ({n['id']})" for n in st.session_state.nodes]

            source_idx = st.selectbox("From", range(len(node_options)), format_func=lambda x: node_options[x])
            target_idx = st.selectbox("To", range(len(node_options)), format_func=lambda x: node_options[x])

            connection_label = st.text_input("Connection Label", value="")

            if st.button("Add Connection", use_container_width=True):
                if source_idx != target_idx:
                    st.session_state.edges.append({
                        'source': st.session_state.nodes[source_idx]['id'],
                        'target': st.session_state.nodes[target_idx]['id'],
                        'label': connection_label,
                        'color': '#999'
                    })
                    st.rerun()
        else:
            st.info("Add at least 2 components to create connections")

        st.markdown("---")
        st.markdown("#### Current Components")

        if st.session_state.nodes:
            for idx, node in enumerate(st.session_state.nodes):
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.text(f"• {node['label']}")
                with col2:
                    if st.button("🗑️", key=f"delete_{idx}"):
                        st.session_state.nodes.pop(idx)
                        # Remove edges connected to this node
                        node_id = node['id']
                        st.session_state.edges = [
                            e for e in st.session_state.edges
                            if e['source'] != node_id and e['target'] != node_id
                        ]
                        st.rerun()

    def _save_diagram(self):
        """Save diagram to file"""
        from datetime import datetime

        filename = f"architecture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = self.diagram_dir / filename

        data = {
            'nodes': st.session_state.nodes,
            'edges': st.session_state.edges,
            'created_at': datetime.now().isoformat()
        }

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def _load_diagram(self):
        """Load diagram from file"""

        diagram_files = list(self.diagram_dir.glob("architecture_*.json"))

        if not diagram_files:
            return

        # Load most recent
        latest_file = max(diagram_files, key=lambda p: p.stat().st_mtime)

        with open(latest_file, 'r') as f:
            data = json.load(f)

        st.session_state.nodes = data.get('nodes', [])
        st.session_state.edges = data.get('edges', [])
