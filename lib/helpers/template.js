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
    string += args[i];
    templateStr += str[i];
    templateStr += `{{ key${i} }}`;
    variables[`key${i}`] = args[i];
  }
  return new Template(string, templateStr, variables);
}
