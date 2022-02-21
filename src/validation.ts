export type Validation<T> = Record<keyof T, string | undefined>;
export type Validator = (value: any, ...props: any[]) => string | undefined;

const emailRegex = new RegExp(
  /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
);
const passwordRegex = new RegExp(
  /^(?=(.*[a-z]){3,})(?=(.*[A-Z]){2,})(?=(.*[0-9]){2,})(?=(.*[!@#$%^&*()\-__+.]){1,}).{8,}$/
);

export const anyErrors = <T extends Object>(errors: Validation<T>): boolean => {
  return Object.values(errors).some((e) => e !== undefined);
};
export const required: Validator = (value: any) =>
  !!value ? undefined : 'Value is required';
export const matching: Validator = (value: any, value2: any) =>
  value === value2 ? undefined : 'Values do not match';
export const isUnique: Validator = (
  value: any,
  values: any[],
  accessor = (value: any): any => value
) =>
  values.some((v) => accessor(v) === accessor(value))
    ? 'Value is not unique'
    : undefined;
export const isEmail: Validator = (value: any) =>
  emailRegex.test(String(value)) ? undefined : 'Not a valid email';
export const strongPassword: Validator = (value: any) =>
  passwordRegex.test(String(value))
    ? undefined
    : '8+ characters with 2 uppercase, 2 numbers, 1 symbol';

export const combine: Validator = (
  item: any,
  ...validation: Array<Validator | any>
) => {
  let result: undefined | string = undefined;
  let f: Validator | undefined = undefined;
  let props: any[] = [];
  for (const v of validation) {
    if (typeof v === 'function') {
      if (f !== undefined) {
        result = f(item, ...props);
      }
      f = v;
      props = [];
    } else {
      props.push(v);
    }

    if (!!result) return result;
  }
  if (f !== undefined) {
    result = f(item, ...props);
  }

  return result;
};
