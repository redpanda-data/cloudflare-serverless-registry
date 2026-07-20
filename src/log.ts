type LogFields = Record<string, string | number | boolean | null | undefined>;

function emit(level: "info" | "warn" | "error", event: string, fields?: LogFields): void {
  const ts = new Date().toISOString();
  let line: string;
  try {
    line = JSON.stringify({ ...fields, level, event, ts });
  } catch {
    // A field violating LogFields at runtime (e.g. circular data smuggled in
    // through `any`) must not take down the request handling that's trying
    // to log it.
    line = JSON.stringify({ level, event, ts });
  }
  if (level === "error") {
    console.error(line);
  } else if (level === "warn") {
    console.warn(line);
  } else {
    console.log(line);
  }
}

export const log = {
  info: (event: string, fields?: LogFields): void => emit("info", event, fields),
  warn: (event: string, fields?: LogFields): void => emit("warn", event, fields),
  error: (event: string, fields?: LogFields): void => emit("error", event, fields),
};
