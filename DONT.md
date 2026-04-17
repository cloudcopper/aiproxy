# Critical Constraints

This file lists explicit constraints for the AIProxy project.

## Configuration

### ❌ DO NOT use multi-format config file libraries

- No Viper, no YAML config files
- Bootstrap settings: CLI flags + environment variables only
- Runtime configuration: JSON storage files only
- See IDEA.md for the authoritative configuration design

### ❌ DO NOT test third-party library behavior

- Don't test flag parsing libraries
- Don't test standard library functions
- Don't test framework internals
- Test business logic that *uses* parsed configuration

## Directory Management

### ❌ DO NOT auto-create operational directories

- All directories must be pre-created by user/deployment

## Adding Constraints

When adding new constraints:
1. Keep entries generic (no specific flag names, file paths, or implementation details)
2. Focus on "what not to do" rather than "why" or "how to do it instead"
3. Update AGENTS.md if reading order needs adjustment

## Frontend

### DO NOT use inline CSS styles in templates
- All styles must be in a dedicated CSS file (`static/styles.css`)
- No `style=` attributes in `.templ` files
- No `el.style = ...` or `el.style.color = ...` in embedded JavaScript
- Use CSS classes instead
