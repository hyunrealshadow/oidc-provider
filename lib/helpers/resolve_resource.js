import { InvalidTarget } from './errors.js';

export default async (ctx, model, config, scopes = model.scopes) => {
  let resource;
  if (config.resourceIndicators.enabled) {
    // eslint-disable-next-line default-case
    switch (true) {
      case !!ctx.oidc.params.resource:
        resource = ctx.oidc.params.resource;
        break;
      case !model.resource:
      case Array.isArray(model.resource) && model.resource.length === 0:
        break;
      case model.resource && !!(await config.resourceIndicators.useGrantedResource(ctx, model)):
      case !ctx.oidc.params.resource && (!config.userinfo.enabled || !scopes.has('openid')):
        resource = model.resource;
        break;
    }

    if (Array.isArray(resource)) {
      resource = await config.resourceIndicators.defaultResource(ctx, ctx.oidc.client, resource);
    }

    if (Array.isArray(resource)) {
      throw new InvalidTarget(true, undefined, '001');
    }

    if (resource && !model.resourceIndicators.has(resource)) {
      throw new InvalidTarget(true, undefined, '002');
    }
  }
  return resource;
};
