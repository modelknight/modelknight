#!/usr/bin/env python3
"""
Compute embeddings for semantic examples in policy YAML files.

This tool reads a policy YAML, computes embeddings for any semantic examples
that don't have them, and writes the updated policy back.

Usage:
    python compute_embeddings.py policy.yaml
    
    # Or to output to a different file:
    python compute_embeddings.py policy.yaml -o policy-with-embeddings.yaml

Requirements:
    pip install sentence-transformers pyyaml
"""

import argparse
import sys
from pathlib import Path

import yaml
from sentence_transformers import SentenceTransformer


def load_policy(path: Path) -> dict:
    """Load policy YAML file."""
    with open(path) as f:
        return yaml.safe_load(f)


def save_policy(path: Path, policy: dict):
    """Save policy YAML file with proper formatting."""
    with open(path, 'w') as f:
        yaml.dump(policy, f, default_flow_style=False, sort_keys=False)


def compute_embeddings_for_policy(policy: dict, model: SentenceTransformer) -> tuple[dict, int]:
    """
    Compute embeddings for semantic examples that don't have them.
    
    Returns:
        Updated policy dict and count of embeddings computed
    """
    count = 0
    
    # Get semantic config if it exists
    semantic = policy.get('semantic')
    if not semantic:
        return policy, count
    
    cases = semantic.get('cases', [])
    for case in cases:
        examples = case.get('examples', [])
        
        # Handle both old string format and new dict format
        updated_examples = []
        for ex in examples:
            if isinstance(ex, str):
                # Old format: just a string, compute embedding
                text = ex
                embedding = model.encode(text, normalize_embeddings=True).tolist()
                updated_examples.append({
                    'text': text,
                    'embedding': embedding
                })
                count += 1
            elif isinstance(ex, dict):
                # New format: check if embedding exists
                if 'embedding' not in ex or ex['embedding'] is None:
                    text = ex['text']
                    embedding = model.encode(text, normalize_embeddings=True).tolist()
                    ex['embedding'] = embedding
                    count += 1
                updated_examples.append(ex)
        
        case['examples'] = updated_examples
    
    return policy, count


def main():
    parser = argparse.ArgumentParser(
        description='Compute embeddings for semantic examples in policy YAML'
    )
    parser.add_argument('input', type=Path, help='Input policy YAML file')
    parser.add_argument('-o', '--output', type=Path, help='Output file (default: overwrite input)')
    parser.add_argument('-m', '--model', default='all-MiniLM-L6-v2',
                       help='SentenceTransformer model name (default: all-MiniLM-L6-v2)')
    
    args = parser.parse_args()
    
    if not args.input.exists():
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    
    output_path = args.output or args.input
    
    print(f"Loading model: {args.model}...")
    model = SentenceTransformer(args.model)
    print(f"Model loaded. Embedding dimension: {model.get_sentence_embedding_dimension()}")
    
    print(f"Loading policy from: {args.input}")
    policy = load_policy(args.input)
    
    print("Computing embeddings...")
    updated_policy, count = compute_embeddings_for_policy(policy, model)
    
    if count == 0:
        print("No embeddings needed - all examples already have embeddings")
    else:
        print(f"Computed {count} embeddings")
        print(f"Saving to: {output_path}")
        save_policy(output_path, updated_policy)
        print("Done!")


if __name__ == '__main__':
    main()
