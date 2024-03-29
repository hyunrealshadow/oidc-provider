export default function htmlSafe(input) {
  if (typeof input === 'number' && Number.isFinite(input)) {
    return `${input}`;
  }

  if (input instanceof String) {
    // eslint-disable-next-line no-param-reassign
    input = input.toString();
  }

  if (typeof input === 'string') {
    return input.replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  if (typeof input === 'boolean') {
    return input.toString();
  }

  return '';
}
