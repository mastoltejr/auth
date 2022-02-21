export const stringArray = (param: any = []): string[] => {
  return (Array.isArray(param) ? param : [param]).map((p) => String(p));
};
