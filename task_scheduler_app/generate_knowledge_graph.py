from langchain_experimental.graph_transformers import LLMGraphTransformer
from langchain_core.documents import Document
from langchain_openai import ChatOpenAI
from pyvis.network import Network
import os

# TODO: Replace with a secure method of storing and accessing the API key
os.environ["OPENAI_API_KEY"] = "YOUR_API_KEY"

def generate_knowledge_graph(text, output_path):
    """
    Generates and visualizes a knowledge graph from input text.

    Args:
        text (str): Input text to convert into a knowledge graph.
        output_path (str): The path to save the generated graph HTML file.
    """
    llm = ChatOpenAI(temperature=0, model_name="gpt-4o")
    graph_transformer = LLMGraphTransformer(llm=llm)

    documents = [Document(page_content=text)]
    graph_documents = graph_transformer.convert_to_graph_documents(documents)

    net = Network(height="750px", width="100%", directed=True, notebook=False, bgcolor="#222222", font_color="white")

    nodes = graph_documents[0].nodes
    relationships = graph_documents[0].relationships

    node_dict = {node.id: node for node in nodes}

    valid_edges = []
    valid_node_ids = set()
    for rel in relationships:
        if rel.source.id in node_dict and rel.target.id in node_dict:
            valid_edges.append(rel)
            valid_node_ids.update([rel.source.id, rel.target.id])

    connected_node_ids = set()
    for rel in relationships:
        connected_node_ids.add(rel.source.id)
        connected_node_ids.add(rel.target.id)

    for node_id in valid_node_ids:
        node = node_dict[node_id]
        try:
            net.add_node(node.id, label=node.id, title=node.type, group=node.type)
        except:
            continue

    for rel in valid_edges:
        try:
            net.add_edge(rel.source.id, rel.target.id, label=rel.type.lower())
        except:
            continue

    net.set_options("""
        {
            "physics": {
                "forceAtlas2Based": {
                    "gravitationalConstant": -100,
                    "centralGravity": 0.01,
                    "springLength": 200,
                    "springConstant": 0.08
                },
                "minVelocity": 0.75,
                "solver": "forceAtlas2Based"
            }
        }
    """)

    try:
        net.save_graph(output_path)
        print(f"Graph saved to {os.path.abspath(output_path)}")
    except Exception as e:
        print(f"Error saving graph: {e}")