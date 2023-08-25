import { pluralize, formatList } from './formatters.js';

class Template extends String {
  template;

  variables;

  constructor(string, templateStr, variables) {
    super(string);
    this.template = templateStr;
    this.variables = variables;
  }
}

export default function template(str, ...args) {
  let string = '';
  let templateStr = '';
  const variables = {};
  for (let i = 0; i < args.length; i += 1) {
    string += str[i];
    if (typeof args[i] === 'object') {
      if (Array.isArray(args[i]) && args[i].length === 2) {
        const { type } = args[i][1];
        switch (type) {
          case 'conjunction':
          case 'disjunction':
            string += formatList(args[i][0], args[i][1]);
            templateStr += str[i];
            templateStr += `{{key${i}, intlList(type: ${type})}}`;
            // eslint-disable-next-line prefer-destructuring
            variables[`key${i}`] = args[i][0];
            break;
          case 'pluralize':
            string += pluralize(args[i][0][0], args[i][0][2]);
            templateStr += str[i];
            templateStr += `{{key${i}, intlPluralize(one: ${args[i][0][0]}, many: ${args[i][0][1]})}}`;
            // eslint-disable-next-line prefer-destructuring
            variables[`key${i}`] = args[i][0][2];
            break;
          default:
            string += JSON.stringify(args[i]);
            templateStr += str[i];
            templateStr += `{{key${i}}}`;
            variables[`key${i}`] = args[i];
        }
      } else {
        string += JSON.stringify(args[i]);
        templateStr += str[i];
        templateStr += `{{key${i}}}`;
        variables[`key${i}`] = args[i];
      }
    } else {
      string += args[i];
      templateStr += str[i];
      templateStr += `{{key${i}}}`;
      variables[`key${i}`] = args[i];
    }
  }
  string += str[str.length - 1];
  templateStr += str[str.length - 1];
  return new Template(string, templateStr, variables);
}
