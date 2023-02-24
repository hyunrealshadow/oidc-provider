import { expect } from 'chai';

import template from '../../lib/helpers/template.js';

describe('template helper', () => {
  it('parse template string to get template information', () => {
    const result = template`Test ${'Hello'} Test ${'World'}`;
    expect(result.template).to.eq('Test {{ key0 }} Test {{ key1 }}');
    expect(result.variables).to.eql({ key0: 'Hello', key1: 'World' });
    expect(result.toString()).to.eq('Test Hello Test World');
  });
});
