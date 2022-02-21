import { Application, ScopeType } from '@prisma/client';

// APPLICATION

// APPLICATION SCOPE

export const isApplicationScope = (value?: string): value is ScopeType => {
  return Object.values(ScopeType).some((s) => s === value);
};
