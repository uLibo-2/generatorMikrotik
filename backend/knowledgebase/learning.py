# -*- coding: utf-8 -*-
from typing import Dict, Any
from backend.knowledgebase.kb import RouterOSKB

class LearningEngine:
    @staticmethod
    def explain_concept(query: str) -> Dict[str, Any]:
        """
        Lookup keyword in learning YAML databases.
        Supports fuzzy matching on query terms.
        """
        learning_db = RouterOSKB.get_learning()
        query_clean = query.lower().strip()

        # Exact match check
        if query_clean in learning_db:
            return learning_db[query_clean]

        # Keyphrase substring matching
        for key, value in learning_db.items():
            name = value.get("name", "").lower()
            explanation = value.get("explanation", "").lower()
            if query_clean in key or query_clean in name or any(word in name or word in explanation for word in query_clean.split()):
                return value

        # Default response if not found
        return {
            "name": f"Пошук для: '{query}'",
            "explanation": "На жаль, за цим запитом детального роз'яснення у базі знань не знайдено.",
            "caveats": "Спробуйте використати ключові слова, такі як: 'fasttrack', 'capsman', або 'bridge_vlan_filtering'.",
            "best_practice": "Зверніться до офіційної документації MikroTik Help Wiki або форумів спільноти.",
            "examples": "# База знань постійно оновлюється"
        }
