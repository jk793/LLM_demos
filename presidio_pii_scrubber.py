from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

class PresidioPIIscrubber():
    def __init__(self, text="", entities=[], score_threshold=0.5, language='en'):
        self.text = text
        self.entities = entities
        self.score_threshold = score_threshold
        self.language = language
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()

    def analyze(self):
        analyzer_result = self.analyzer.analyze(text=self.text, entities=self.entities, language=self.language)
        selected_res = [res for res in analyzer_result if res.score >= self.score_threshold]

        PII_type_counts = {}
        for res in selected_res:
            entity_type = res.entity_type
            if entity_type in PII_type_counts:
                PII_type_counts[entity_type] += 1
            else:
                PII_type_counts[entity_type] = 1

        return selected_res, PII_type_counts

    def anonymize(self, analyzer_result):
        anonymized_text = self.anonymizer.anonymize(text=self.text, analyzer_results=analyzer_result)
        return anonymized_text.text
