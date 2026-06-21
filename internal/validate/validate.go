package validate

import (
	"fmt"

	"github.com/vojkovic/egresso/internal/dial"
	"github.com/vojkovic/egresso/internal/pool"
)

func Prefixes(p *pool.Pool) error {
	for _, prefix := range p.Prefixes() {
		addr, err := p.PickFrom(prefix)
		if err != nil {
			return fmt.Errorf("%s: %w", prefix, err)
		}
		if err := dial.CanBind(addr); err != nil {
			return fmt.Errorf("%s not routable (check local routes and ip_nonlocal_bind): %w", prefix, err)
		}
	}
	return nil
}
