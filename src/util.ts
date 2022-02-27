export const stringArray = (param: any = []): string[] => {
  return (Array.isArray(param) ? param : [param]).map((p) => String(p));
};

export const splitToken = (token: string): [string, string] => {
  const index = token.lastIndexOf('.');
  return [token.substring(0, index), token.substring(index + 1)];
};
