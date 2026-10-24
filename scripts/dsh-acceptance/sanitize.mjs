// Path forms differ between plain logs, JSON, file URLs, and Windows stacks.
// Sanitize before serialization as well as at each persisted text boundary.
export function sanitizeEvidence(value, { roots = [], secrets = [] } = {}) {
  let text = String(value)
  for (const [root, replacement] of roots) {
    const normalized = root.replaceAll('\\', '/')
    const forms = new Set([root, normalized, encodeURI(normalized)])
    for (const form of [...forms]) forms.add(JSON.stringify(form).slice(1, -1))
    for (const form of [...forms].sort((left, right) => right.length - left.length)) {
      text = text.split(form).join(replacement)
    }
  }
  for (const secret of secrets) if (secret) text = text.split(secret).join('<synthetic-credential>')
  return text
}
