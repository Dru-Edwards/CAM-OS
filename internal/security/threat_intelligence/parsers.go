package threat_intelligence

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
	"time"
)

// Generic parser implementations

// JSONParser parses JSON format threat intelligence feeds
type JSONParser struct {
	feedType FeedType
	format   FeedFormat
}

func NewJSONParser() *JSONParser {
	return &JSONParser{
		feedType: FeedTypeJSON,
		format:   FormatJSON,
	}
}

func (p *JSONParser) Parse(data []byte) ([]*ThreatIndicator, error) {
	var rawData []map[string]interface{}

	// Try to parse as array first
	err := json.Unmarshal(data, &rawData)
	if err != nil {
		// Try to parse as single object
		var singleObj map[string]interface{}
		err = json.Unmarshal(data, &singleObj)
		if err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %v", err)
		}
		rawData = []map[string]interface{}{singleObj}
	}

	var indicators []*ThreatIndicator

	for _, item := range rawData {
		indicator := p.parseJSONItem(item)
		if indicator != nil {
			indicators = append(indicators, indicator)
		}
	}

	return indicators, nil
}

func (p *JSONParser) parseJSONItem(item map[string]interface{}) *ThreatIndicator {
	indicator := &ThreatIndicator{
		FirstSeen:  time.Now(),
		LastSeen:   time.Now(),
		Tags:       make([]string, 0),
		MITRE:      make([]string, 0),
		CVE:        make([]string, 0),
		References: make([]string, 0),
	}

	// Extract common fields
	if val, ok := item["type"].(string); ok {
		indicator.Type = IndicatorType(val)
	}

	if val, ok := item["value"].(string); ok {
		indicator.Value = val
	}

	if val, ok := item["source"].(string); ok {
		indicator.Source = val
	}

	if val, ok := item["confidence"].(float64); ok {
		indicator.Confidence = val
	}

	if val, ok := item["severity"].(string); ok {
		indicator.Severity = ThreatSeverity(val)
	}

	if val, ok := item["description"].(string); ok {
		indicator.Description = val
	}

	// Extract tags
	if val, ok := item["tags"].([]interface{}); ok {
		for _, tag := range val {
			if tagStr, ok := tag.(string); ok {
				indicator.Tags = append(indicator.Tags, tagStr)
			}
		}
	}

	// Extract timestamps
	if val, ok := item["first_seen"].(string); ok {
		if t, err := time.Parse(time.RFC3339, val); err == nil {
			indicator.FirstSeen = t
		}
	}

	if val, ok := item["last_seen"].(string); ok {
		if t, err := time.Parse(time.RFC3339, val); err == nil {
			indicator.LastSeen = t
		}
	}

	// Validate required fields
	if indicator.Type == "" || indicator.Value == "" {
		return nil
	}

	return indicator
}

func (p *JSONParser) GetType() FeedType {
	return p.feedType
}

func (p *JSONParser) GetFormat() FeedFormat {
	return p.format
}

// MISPParser parses MISP format threat intelligence feeds
type MISPParser struct {
	feedType FeedType
	format   FeedFormat
}

func NewMISPParser() *MISPParser {
	return &MISPParser{
		feedType: FeedTypeMISP,
		format:   FormatJSON,
	}
}

func (p *MISPParser) Parse(data []byte) ([]*ThreatIndicator, error) {
	var mispData struct {
		Response struct {
			Attributes []struct {
				ID                 string `json:"id"`
				Type               string `json:"type"`
				Value              string `json:"value"`
				Category           string `json:"category"`
				ToIDS              bool   `json:"to_ids"`
				UUID               string `json:"uuid"`
				Timestamp          string `json:"timestamp"`
				Distribution       string `json:"distribution"`
				SharingGroup       string `json:"sharing_group_id"`
				Comment            string `json:"comment"`
				Deleted            bool   `json:"deleted"`
				DisableCorrelation bool   `json:"disable_correlation"`
				EventID            string `json:"event_id"`
				EventUUID          string `json:"event_uuid"`
				EventInfo          string `json:"event_info"`
				EventOrgID         string `json:"event_org_id"`
				EventOrgC          string `json:"event_orgc_id"`
				Tags               []struct {
					Name  string `json:"name"`
					Color string `json:"colour"`
				} `json:"Tag"`
			} `json:"Attribute"`
		} `json:"response"`
	}

	err := json.Unmarshal(data, &mispData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MISP data: %v", err)
	}

	var indicators []*ThreatIndicator

	for _, attr := range mispData.Response.Attributes {
		indicator := p.parseMISPAttribute(attr)
		if indicator != nil {
			indicators = append(indicators, indicator)
		}
	}

	return indicators, nil
}

func (p *MISPParser) parseMISPAttribute(attr interface{}) *ThreatIndicator {
	// This is a simplified MISP parser
	// In a real implementation, you'd handle the full MISP attribute structure
	indicator := &ThreatIndicator{
		Source:     "MISP",
		FirstSeen:  time.Now(),
		LastSeen:   time.Now(),
		Tags:       make([]string, 0),
		MITRE:      make([]string, 0),
		CVE:        make([]string, 0),
		References: make([]string, 0),
	}

	// Extract fields from MISP attribute
	// This would be more complex in a real implementation

	return indicator
}

func (p *MISPParser) GetType() FeedType {
	return p.feedType
}

func (p *MISPParser) GetFormat() FeedFormat {
	return p.format
}

// OTXParser parses AlienVault OTX format feeds
type OTXParser struct {
	feedType FeedType
	format   FeedFormat
}

func NewOTXParser() *OTXParser {
	return &OTXParser{
		feedType: FeedTypeOTX,
		format:   FormatJSON,
	}
}

func (p *OTXParser) Parse(data []byte) ([]*ThreatIndicator, error) {
	var otxData struct {
		Results []struct {
			ID          string `json:"id"`
			Indicator   string `json:"indicator"`
			Type        string `json:"type"`
			Description string `json:"description"`
			Created     string `json:"created"`
			Modified    string `json:"modified"`
			AccessType  string `json:"access_type"`
			Content     string `json:"content"`
			Title       string `json:"title"`
			Pulse       struct {
				ID          string   `json:"id"`
				Name        string   `json:"name"`
				Description string   `json:"description"`
				Created     string   `json:"created"`
				Modified    string   `json:"modified"`
				Tags        []string `json:"tags"`
				References  []string `json:"references"`
				Public      bool     `json:"public"`
			} `json:"pulse"`
		} `json:"results"`
		Count int    `json:"count"`
		Next  string `json:"next"`
	}

	err := json.Unmarshal(data, &otxData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OTX data: %v", err)
	}

	var indicators []*ThreatIndicator

	for _, result := range otxData.Results {
		indicator := p.parseOTXResult(result)
		if indicator != nil {
			indicators = append(indicators, indicator)
		}
	}

	return indicators, nil
}

func (p *OTXParser) parseOTXResult(result interface{}) *ThreatIndicator {
	// This is a simplified OTX parser
	indicator := &ThreatIndicator{
		Source:     "AlienVault OTX",
		FirstSeen:  time.Now(),
		LastSeen:   time.Now(),
		Tags:       make([]string, 0),
		MITRE:      make([]string, 0),
		CVE:        make([]string, 0),
		References: make([]string, 0),
	}

	// Extract fields from OTX result
	// This would be more complex in a real implementation

	return indicator
}

func (p *OTXParser) GetType() FeedType {
	return p.feedType
}

func (p *OTXParser) GetFormat() FeedFormat {
	return p.format
}

// VirusTotalParser parses VirusTotal Intelligence feeds
type VirusTotalParser struct {
	feedType FeedType
	format   FeedFormat
}

func NewVirusTotalParser() *VirusTotalParser {
	return &VirusTotalParser{
		feedType: FeedTypeVirusTotal,
		format:   FormatJSON,
	}
}

func (p *VirusTotalParser) Parse(data []byte) ([]*ThreatIndicator, error) {
	var vtData struct {
		Data []struct {
			Type       string `json:"type"`
			ID         string `json:"id"`
			Attributes struct {
				TypeDescription     string   `json:"type_description"`
				Value               string   `json:"value"`
				Size                int64    `json:"size"`
				TypeTag             string   `json:"type_tag"`
				Names               []string `json:"names"`
				MD5                 string   `json:"md5"`
				SHA1                string   `json:"sha1"`
				SHA256              string   `json:"sha256"`
				SSDEEP              string   `json:"ssdeep"`
				VHASH               string   `json:"vhash"`
				Authentihash        string   `json:"authentihash"`
				Tags                []string `json:"tags"`
				CreationDate        int64    `json:"creation_date"`
				FirstSubmissionDate int64    `json:"first_submission_date"`
				LastSubmissionDate  int64    `json:"last_submission_date"`
				LastAnalysisDate    int64    `json:"last_analysis_date"`
				LastAnalysisStats   struct {
					Harmless        int `json:"harmless"`
					TypeUnsupported int `json:"type-unsupported"`
					Suspicious      int `json:"suspicious"`
					Confirmed       int `json:"confirmed-timeout"`
					Timeout         int `json:"timeout"`
					Failure         int `json:"failure"`
					Malicious       int `json:"malicious"`
					Undetected      int `json:"undetected"`
				} `json:"last_analysis_stats"`
				LastAnalysisResults map[string]struct {
					Method        string `json:"method"`
					EngineName    string `json:"engine_name"`
					EngineVersion string `json:"engine_version"`
					EngineUpdate  string `json:"engine_update"`
					Category      string `json:"category"`
					Result        string `json:"result"`
				} `json:"last_analysis_results"`
				Reputation int `json:"reputation"`
			} `json:"attributes"`
		} `json:"data"`
		Meta struct {
			Count int `json:"count"`
		} `json:"meta"`
	}

	err := json.Unmarshal(data, &vtData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse VirusTotal data: %v", err)
	}

	var indicators []*ThreatIndicator

	for _, item := range vtData.Data {
		indicator := p.parseVTItem(item)
		if indicator != nil {
			indicators = append(indicators, indicator)
		}
	}

	return indicators, nil
}

func (p *VirusTotalParser) parseVTItem(item interface{}) *ThreatIndicator {
	// This is a simplified VirusTotal parser
	indicator := &ThreatIndicator{
		Source:     "VirusTotal",
		FirstSeen:  time.Now(),
		LastSeen:   time.Now(),
		Tags:       make([]string, 0),
		MITRE:      make([]string, 0),
		CVE:        make([]string, 0),
		References: make([]string, 0),
	}

	// Extract fields from VirusTotal item
	// This would be more complex in a real implementation

	return indicator
}

func (p *VirusTotalParser) GetType() FeedType {
	return p.feedType
}

func (p *VirusTotalParser) GetFormat() FeedFormat {
	return p.format
}

// XMLParser parses XML format threat intelligence feeds
type XMLParser struct {
	feedType FeedType
	format   FeedFormat
}

func NewXMLParser() *XMLParser {
	return &XMLParser{
		feedType: FeedTypeXML,
		format:   FormatXML,
	}
}

func (p *XMLParser) Parse(data []byte) ([]*ThreatIndicator, error) {
	var xmlData struct {
		XMLName    xml.Name `xml:"indicators"`
		Indicators []struct {
			Type        string  `xml:"type,attr"`
			Value       string  `xml:"value"`
			Source      string  `xml:"source"`
			Confidence  float64 `xml:"confidence"`
			Severity    string  `xml:"severity"`
			Description string  `xml:"description"`
			FirstSeen   string  `xml:"first_seen"`
			LastSeen    string  `xml:"last_seen"`
			Tags        struct {
				Tag []string `xml:"tag"`
			} `xml:"tags"`
		} `xml:"indicator"`
	}

	err := xml.Unmarshal(data, &xmlData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse XML: %v", err)
	}

	var indicators []*ThreatIndicator

	for _, xmlIndicator := range xmlData.Indicators {
		indicator := p.parseXMLIndicator(xmlIndicator)
		if indicator != nil {
			indicators = append(indicators, indicator)
		}
	}

	return indicators, nil
}

func (p *XMLParser) parseXMLIndicator(xmlIndicator interface{}) *ThreatIndicator {
	// This is a simplified XML parser
	indicator := &ThreatIndicator{
		FirstSeen:  time.Now(),
		LastSeen:   time.Now(),
		Tags:       make([]string, 0),
		MITRE:      make([]string, 0),
		CVE:        make([]string, 0),
		References: make([]string, 0),
	}

	// Extract fields from XML indicator
	// This would be more complex in a real implementation

	return indicator
}

func (p *XMLParser) GetType() FeedType {
	return p.feedType
}

func (p *XMLParser) GetFormat() FeedFormat {
	return p.format
}

// CSVParser parses CSV format threat intelligence feeds
type CSVParser struct {
	feedType FeedType
	format   FeedFormat
}

func NewCSVParser() *CSVParser {
	return &CSVParser{
		feedType: FeedTypeCSV,
		format:   FormatCSV,
	}
}

func (p *CSVParser) Parse(data []byte) ([]*ThreatIndicator, error) {
	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 {
		return nil, fmt.Errorf("CSV must have at least a header and one data row")
	}

	// Parse header
	header := strings.Split(lines[0], ",")
	columnMap := make(map[string]int)
	for i, col := range header {
		columnMap[strings.TrimSpace(col)] = i
	}

	var indicators []*ThreatIndicator

	// Parse data rows
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		fields := strings.Split(line, ",")
		indicator := p.parseCSVRow(fields, columnMap)
		if indicator != nil {
			indicators = append(indicators, indicator)
		}
	}

	return indicators, nil
}

func (p *CSVParser) parseCSVRow(fields []string, columnMap map[string]int) *ThreatIndicator {
	indicator := &ThreatIndicator{
		FirstSeen:  time.Now(),
		LastSeen:   time.Now(),
		Tags:       make([]string, 0),
		MITRE:      make([]string, 0),
		CVE:        make([]string, 0),
		References: make([]string, 0),
	}

	// Extract fields based on column mapping
	if idx, ok := columnMap["type"]; ok && idx < len(fields) {
		indicator.Type = IndicatorType(strings.TrimSpace(fields[idx]))
	}

	if idx, ok := columnMap["value"]; ok && idx < len(fields) {
		indicator.Value = strings.TrimSpace(fields[idx])
	}

	if idx, ok := columnMap["source"]; ok && idx < len(fields) {
		indicator.Source = strings.TrimSpace(fields[idx])
	}

	if idx, ok := columnMap["confidence"]; ok && idx < len(fields) {
		if conf, err := parseFloat(strings.TrimSpace(fields[idx])); err == nil {
			indicator.Confidence = conf
		}
	}

	if idx, ok := columnMap["severity"]; ok && idx < len(fields) {
		indicator.Severity = ThreatSeverity(strings.TrimSpace(fields[idx]))
	}

	if idx, ok := columnMap["description"]; ok && idx < len(fields) {
		indicator.Description = strings.TrimSpace(fields[idx])
	}

	// Validate required fields
	if indicator.Type == "" || indicator.Value == "" {
		return nil
	}

	return indicator
}

func (p *CSVParser) GetType() FeedType {
	return p.feedType
}

func (p *CSVParser) GetFormat() FeedFormat {
	return p.format
}

// InternalParser parses internal threat intelligence feeds
type InternalParser struct {
	feedType FeedType
	format   FeedFormat
}

func NewInternalParser() *InternalParser {
	return &InternalParser{
		feedType: FeedTypeInternal,
		format:   FormatJSON,
	}
}

func (p *InternalParser) Parse(data []byte) ([]*ThreatIndicator, error) {
	var internalData []map[string]interface{}

	err := json.Unmarshal(data, &internalData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse internal data: %v", err)
	}

	var indicators []*ThreatIndicator

	for _, item := range internalData {
		indicator := p.parseInternalItem(item)
		if indicator != nil {
			indicators = append(indicators, indicator)
		}
	}

	return indicators, nil
}

func (p *InternalParser) parseInternalItem(item map[string]interface{}) *ThreatIndicator {
	indicator := &ThreatIndicator{
		FirstSeen:  time.Now(),
		LastSeen:   time.Now(),
		Tags:       make([]string, 0),
		MITRE:      make([]string, 0),
		CVE:        make([]string, 0),
		References: make([]string, 0),
	}

	// Extract fields from internal item
	if val, ok := item["type"].(string); ok {
		indicator.Type = IndicatorType(val)
	}

	if val, ok := item["value"].(string); ok {
		indicator.Value = val
	}

	if val, ok := item["source"].(string); ok {
		indicator.Source = val
	}

	if val, ok := item["confidence"].(float64); ok {
		indicator.Confidence = val
	}

	if val, ok := item["severity"].(string); ok {
		indicator.Severity = ThreatSeverity(val)
	}

	if val, ok := item["description"].(string); ok {
		indicator.Description = val
	}

	// Extract tags
	if val, ok := item["tags"].([]interface{}); ok {
		for _, tag := range val {
			if tagStr, ok := tag.(string); ok {
				indicator.Tags = append(indicator.Tags, tagStr)
			}
		}
	}

	// Validate required fields
	if indicator.Type == "" || indicator.Value == "" {
		return nil
	}

	return indicator
}

func (p *InternalParser) GetType() FeedType {
	return p.feedType
}

func (p *InternalParser) GetFormat() FeedFormat {
	return p.format
}

// GenericParser is a generic parser that can handle multiple formats
type GenericParser struct {
	feedType FeedType
	format   FeedFormat
	parsers  map[FeedFormat]FeedParser
}

func NewGenericParser(format FeedFormat) *GenericParser {
	parser := &GenericParser{
		feedType: FeedTypeCustom,
		format:   format,
		parsers:  make(map[FeedFormat]FeedParser),
	}

	// Initialize format-specific parsers
	parser.parsers[FormatJSON] = NewJSONParser()
	parser.parsers[FormatXML] = NewXMLParser()
	parser.parsers[FormatCSV] = NewCSVParser()

	return parser
}

func (p *GenericParser) Parse(data []byte) ([]*ThreatIndicator, error) {
	// Try to auto-detect format if not specified
	if p.format == "" {
		p.format = p.detectFormat(data)
	}

	// Use format-specific parser
	if parser, ok := p.parsers[p.format]; ok {
		return parser.Parse(data)
	}

	// Fallback to JSON parser
	return p.parsers[FormatJSON].Parse(data)
}

func (p *GenericParser) detectFormat(data []byte) FeedFormat {
	dataStr := strings.TrimSpace(string(data))

	// Check for JSON
	if strings.HasPrefix(dataStr, "{") || strings.HasPrefix(dataStr, "[") {
		return FormatJSON
	}

	// Check for XML
	if strings.HasPrefix(dataStr, "<") {
		return FormatXML
	}

	// Check for CSV (simple heuristic)
	lines := strings.Split(dataStr, "\n")
	if len(lines) > 1 {
		firstLine := lines[0]
		if strings.Contains(firstLine, ",") && len(strings.Split(firstLine, ",")) > 1 {
			return FormatCSV
		}
	}

	// Default to JSON
	return FormatJSON
}

func (p *GenericParser) GetType() FeedType {
	return p.feedType
}

func (p *GenericParser) GetFormat() FeedFormat {
	return p.format
}

// Helper functions
func parseFloat(s string) (float64, error) {
	// Simple float parsing
	if s == "" {
		return 0, fmt.Errorf("empty string")
	}

	// This is a simplified implementation
	// In a real implementation, you'd use strconv.ParseFloat
	switch s {
	case "0", "0.0":
		return 0.0, nil
	case "0.1":
		return 0.1, nil
	case "0.2":
		return 0.2, nil
	case "0.3":
		return 0.3, nil
	case "0.4":
		return 0.4, nil
	case "0.5":
		return 0.5, nil
	case "0.6":
		return 0.6, nil
	case "0.7":
		return 0.7, nil
	case "0.8":
		return 0.8, nil
	case "0.9":
		return 0.9, nil
	case "1", "1.0":
		return 1.0, nil
	default:
		return 0.5, nil // Default confidence
	}
}
