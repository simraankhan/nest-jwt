import { ExecutionContext, createParamDecorator } from '@nestjs/common';

export const GetUser = createParamDecorator(
  (data: string | undefined, ctx: ExecutionContext) => {
    const user = ctx.switchToHttp().getRequest().user;
    if (!data) return user;
    return user[data];
  },
);
