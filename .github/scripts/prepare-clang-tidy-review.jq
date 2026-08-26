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

def valid_comment:
  type == "object" and
  ((.body | type) == "string") and
  ((.body | length) > 0 and (.body | length) <= 65536) and
  (.path | safe_path) and
  (.line | positive_integer) and
  ((has("start_line") | not) or
   ((.start_line | positive_integer) and .start_line <= .line));

def canonical_comment:
  {body, path, line, side: "RIGHT"} +
  (if has("start_line") then
     {start_line, start_side: "RIGHT"}
   else
     {}
   end);

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
    body: "clang-tidy made some suggestions",
    event: "COMMENT",
    comments: [.comments[] | canonical_comment]
  }
end
