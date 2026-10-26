package protocol

import (
	"fmt"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func registerQualifiedURI(c *jsonschema.Compiler) error {
	// The library uses the same parser for URI and IRI. Preserve its URI checks,
	// but reject unescaped non-ASCII bytes as required by this schema's uri format.
	base := jsonschema.NewCompiler()
	base.AssertFormat()
	base.UseLoader(offlineLoader{})
	if err := base.AddResource("urn:neticora:uri", map[string]any{"type": "string", "format": "uri"}); err != nil {
		return err
	}
	validator, err := base.Compile("urn:neticora:uri")
	if err != nil {
		return err
	}
	c.RegisterFormat(&jsonschema.Format{Name: "uri", Validate: func(value any) error {
		text, ok := value.(string)
		if !ok {
			return nil
		}
		for i := 0; i < len(text); i++ {
			if text[i] >= 0x80 {
				return fmt.Errorf("URI requires escaped non-ASCII characters")
			}
		}
		return validator.Validate(value)
	}})
	return nil
}
