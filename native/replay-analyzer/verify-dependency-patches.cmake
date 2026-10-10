cmake_minimum_required(VERSION 3.16)

# Verify one dependency without changing its index. Each patch's `index` line
# contains the expected post-image blob id. Comparing those ids checks the
# complete contents of every patched file, not just a few signature lines or
# whether the reverse patch happens to apply. Comparing `git status` paths then
# rejects any extra tracked or untracked source changes.
function(verify_dependency label source_dir expected_revision patch_file)
  foreach(required GIT_EXECUTABLE source_dir patch_file)
    if(NOT ${required})
      message(FATAL_ERROR "${label}: required verifier input ${required} is missing")
    endif()
  endforeach()

  execute_process(
    COMMAND "${GIT_EXECUTABLE}" -C "${source_dir}" rev-parse HEAD
    RESULT_VARIABLE revision_result
    OUTPUT_VARIABLE actual_revision
    ERROR_VARIABLE revision_error
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if(NOT revision_result EQUAL 0)
    message(FATAL_ERROR "${label}: cannot read Git revision: ${revision_error}")
  endif()
  if(NOT actual_revision STREQUAL expected_revision)
    message(FATAL_ERROR
      "${label}: expected revision ${expected_revision}, found ${actual_revision}. "
      "Reset the dependency to its pinned revision and re-apply ${patch_file}"
    )
  endif()

  file(STRINGS "${patch_file}" patch_lines)
  set(expected_paths)
  set(current_path "")
  set(current_path_hashed FALSE)
  foreach(line IN LISTS patch_lines)
    if(line MATCHES "^diff --git a/([^ ]+) b/([^ ]+)$")
      if(current_path AND NOT current_path_hashed)
        message(FATAL_ERROR "${label}: patch has no post-image hash for ${current_path}")
      endif()
      set(current_path "${CMAKE_MATCH_2}")
      set(current_path_hashed FALSE)
      list(APPEND expected_paths "${current_path}")
    elseif(current_path AND line MATCHES "^index [0-9a-f]+\\.\\.([0-9a-f]+)( .*)?$")
      set(expected_hash "${CMAKE_MATCH_1}")
      execute_process(
        COMMAND "${GIT_EXECUTABLE}" -C "${source_dir}" hash-object
          "--path=${current_path}" "${current_path}"
        RESULT_VARIABLE hash_result
        OUTPUT_VARIABLE actual_hash
        ERROR_VARIABLE hash_error
        OUTPUT_STRIP_TRAILING_WHITESPACE
      )
      if(NOT hash_result EQUAL 0)
        message(FATAL_ERROR "${label}: cannot hash patched file ${current_path}: ${hash_error}")
      endif()
      string(FIND "${actual_hash}" "${expected_hash}" hash_prefix_position)
      if(NOT hash_prefix_position EQUAL 0)
        message(FATAL_ERROR
          "${label}: ${current_path} does not match the committed patch "
          "(expected blob ${expected_hash}, found ${actual_hash})"
        )
      endif()
      set(current_path_hashed TRUE)
    endif()
  endforeach()
  if(current_path AND NOT current_path_hashed)
    message(FATAL_ERROR "${label}: patch has no post-image hash for ${current_path}")
  endif()
  if(NOT expected_paths)
    message(FATAL_ERROR "${label}: no patched files found in ${patch_file}")
  endif()

  execute_process(
    COMMAND "${GIT_EXECUTABLE}" -C "${source_dir}" status
      --porcelain=v1 --untracked-files=all
    RESULT_VARIABLE status_result
    OUTPUT_VARIABLE status_output
    ERROR_VARIABLE status_error
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if(NOT status_result EQUAL 0)
    message(FATAL_ERROR "${label}: cannot inspect working tree: ${status_error}")
  endif()

  set(actual_paths)
  if(status_output)
    string(REPLACE "\r\n" "\n" status_output "${status_output}")
    string(REPLACE "\n" ";" status_lines "${status_output}")
    foreach(status_line IN LISTS status_lines)
      string(LENGTH "${status_line}" status_length)
      if(status_length LESS 4)
        message(FATAL_ERROR "${label}: cannot parse Git status line '${status_line}'")
      endif()
      string(SUBSTRING "${status_line}" 3 -1 status_path)
      if(status_path MATCHES " -> ")
        message(FATAL_ERROR "${label}: unexpected renamed path in Git status: ${status_line}")
      endif()
      list(APPEND actual_paths "${status_path}")
    endforeach()
  endif()

  list(REMOVE_DUPLICATES expected_paths)
  list(REMOVE_DUPLICATES actual_paths)
  list(SORT expected_paths)
  list(SORT actual_paths)
  if(NOT actual_paths STREQUAL expected_paths)
    string(JOIN ", " expected_display ${expected_paths})
    string(JOIN ", " actual_display ${actual_paths})
    message(FATAL_ERROR
      "${label}: working-tree changes do not exactly match the committed patch. "
      "Expected [${expected_display}], found [${actual_display}]"
    )
  endif()

  list(LENGTH expected_paths patched_file_count)
  message(STATUS "${label}: ${actual_revision}, ${patched_file_count} patched files verified")
endfunction()

verify_dependency(
  "OpenBW"
  "${OPENBW_DIR}"
  "8265ec449b903e0752060a00ed5f930a3656bf00"
  "${OPENBW_PATCH}"
)
verify_dependency(
  "OpenBW BWAPI"
  "${OPENBW_BWAPI_DIR}"
  "48124ba8ed1b4d52b3dfd52acbaf34afb9a37fe2"
  "${BWAPI_PATCH}"
)
