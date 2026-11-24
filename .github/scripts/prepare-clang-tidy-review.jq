# Convert untrusted action output into a bounded advisory review.
def positive_integer:
  type == "number" and . >= 1 and . <= 2147483647 and floor == .;

def safe_path:
  type == "string" and
  length > 0 and length <= 4096 and
  (startswith("/") | not) and
  (contains("\\") | not) and
  (index("\u0000") == null) and
  (split("/") | all(. != "" and . != "." and . != ".."));

def diagnostic_body:
  split("\n")[0] | rtrimstr("\r");

def valid_comment:
  type == "object" and
  ((.body | type) == "string") and
  ((.body | length) > 0 and (.body | length) <= 65536) and
  ((.body | diagnostic_body | length) > 0 and
   (.body | diagnostic_body | length) <= 4096) and
  (.path | safe_path) and
  (.line | positive_integer) and
  ((has("start_line") | not) or
   ((.start_line | positive_integer) and .start_line <= .line));

def canonical_comment:
  # The action calculates fix text with character offsets, but clang-tidy
  # reports byte offsets. Do not pass potentially corrupt fix blocks on.
  {
    body: (.body | diagnostic_body),
    path,
    line: (.start_line // .line),
    side: "RIGHT"
  };

if . == null then
  null
elif type != "object" or (.comments | type) != "array" then
  error("review must be null or contain a comments array")
elif (.comments | length) == 0 then
  null
elif (.comments | length) > 1000 then
  error("review contains more than 1000 comments")
elif (all(.comments[]; valid_comment) | not) then
  error("review contains an invalid comment")
else
  {
    body: "clang-tidy reported warnings",
    event: "COMMENT",
    comments: [.comments[] | canonical_comment]
  }
end
