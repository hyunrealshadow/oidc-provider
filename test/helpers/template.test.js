import { expect } from 'chai';

import template from '../../lib/helpers/template.js';

describe('template helper', () => {
  it('parse template string to get template information', () => {
    const result = template`Test ${'Hello'} Test ${'World'}`;
    expect(result.template).to.eq('Test {{key0}} Test {{key1}}');
    expect(result.variables).to.eql({ key0: 'Hello', key1: 'World' });
    expect(result.toString()).to.eq('Test Hello Test World');
  });
  it('parse template string to get template information with intl format array', () => {
    const result = template`Test ${[['A1', 'A2', 'A3'], { type: 'conjunction' }]} Test ${[['B1', 'B2', 'B3'], { type: 'disjunction' }]}`;
    expect(result.template).to.eq('Test {{key0, intlList(type: conjunction)}} Test {{key1, intlList(type: disjunction)}}');
    expect(result.variables).to.eql({ key0: ['A1', 'A2', 'A3'], key1: ['B1', 'B2', 'B3'] });
    expect(result.toString()).to.eq('Test \'A1\', \'A2\', and \'A3\' Test \'B1\', \'B2\', or \'B3\'');
  });
  it('parse template string to get template information with intl format array and pluralize', () => {
    const result = template`Test ${[['param', 'params', 1], { type: 'pluralize' }]} Test ${[['param', 'params', 2], { type: 'pluralize' }]}`;
    expect(result.template).to.eq('Test {{key0, intlPlural(one: param; other: params)}} Test {{key1, intlPlural(one: param; other: params)}}');
    expect(result.variables).to.eql({ key0: 1, key1: 2 });
    expect(result.toString()).to.eq('Test param Test params');
  });
  it('parse template string to get template information, string param length greater than variables length', () => {
    const result = template`Test ${'Hello'} Test ${'World'} Test`;
    expect(result.template).to.eq('Test {{key0}} Test {{key1}} Test');
    expect(result.variables).to.eql({ key0: 'Hello', key1: 'World' });
    expect(result.toString()).to.eq('Test Hello Test World Test');
  });
  it('parse template string to get template information, string param length less than variables length', () => {
    const result = template`Test ${'Hello'} Test ${'World'} Test ${'!'}`;
    expect(result.template).to.eq('Test {{key0}} Test {{key1}} Test {{key2}}');
    expect(result.variables).to.eql({ key0: 'Hello', key1: 'World', key2: '!' });
    expect(result.toString()).to.eq('Test Hello Test World Test !');
  });
});
