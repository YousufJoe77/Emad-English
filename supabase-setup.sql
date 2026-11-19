-- Emad English: setup for the existing schema.
-- Run in Supabase SQL Editor. Does NOT drop or recreate your tables.
-- Your existing columns are: submissions(id bigint, student_name, stage, submitted_at)
-- submission_files(id bigint, submission_id bigint, original_name, storage_path, created_at)

-- 1) Create a private bucket for homework files (safe to run more than once).
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
  'homework', 'homework', false, 10485760,
  ARRAY['application/pdf','application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'image/jpeg','image/png','image/webp']
)
ON CONFLICT (id) DO UPDATE SET
  public = false,
  file_size_limit = 10485760,
  allowed_mime_types = EXCLUDED.allowed_mime_types;

-- 2) Ensure RLS is on.
ALTER TABLE public.submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.submission_files ENABLE ROW LEVEL SECURITY;

-- 3) Remove only policies with these setup-script names, so reruns are safe.
DROP POLICY IF EXISTS "emad_teacher_read_submissions" ON public.submissions;
DROP POLICY IF EXISTS "emad_teacher_read_submission_files" ON public.submission_files;
DROP POLICY IF EXISTS "emad_student_upload_homework_files" ON storage.objects;
DROP POLICY IF EXISTS "emad_teacher_read_homework_files" ON storage.objects;

-- Teachers authenticated through Supabase can read submitted records.
CREATE POLICY "emad_teacher_read_submissions"
ON public.submissions FOR SELECT TO authenticated
USING (auth.uid() IS NOT NULL);

CREATE POLICY "emad_teacher_read_submission_files"
ON public.submission_files FOR SELECT TO authenticated
USING (auth.uid() IS NOT NULL);

-- Allow anonymous students to upload into the private bucket.
-- This is intentionally limited to INSERT and the homework bucket.
CREATE POLICY "emad_student_upload_homework_files"
ON storage.objects FOR INSERT TO anon, authenticated
WITH CHECK (bucket_id = 'homework');

-- Only signed-in teachers can read objects from the private homework bucket.
CREATE POLICY "emad_teacher_read_homework_files"
ON storage.objects FOR SELECT TO authenticated
USING (bucket_id = 'homework');

-- 4) RPC inserts the submission + file metadata without exposing public SELECT.
CREATE OR REPLACE FUNCTION public.submit_homework(
  p_student_name text,
  p_stage text,
  p_original_name text,
  p_storage_path text
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  new_submission_id bigint;
BEGIN
  IF p_student_name IS NULL OR length(trim(p_student_name)) < 2 OR length(p_student_name) > 120 THEN
    RAISE EXCEPTION 'Please enter a valid student name';
  END IF;
  IF p_stage IS NULL OR p_stage NOT IN (
    '2nd Preparatory','3rd Preparatory','1st Secondary','2nd Secondary','3rd Secondary'
  ) THEN
    RAISE EXCEPTION 'Invalid stage';
  END IF;
  IF p_original_name IS NULL OR length(p_original_name) < 1 OR length(p_original_name) > 255 THEN
    RAISE EXCEPTION 'Invalid file name';
  END IF;
  IF p_storage_path IS NULL OR length(p_storage_path) > 500 OR p_storage_path !~ '^[0-9a-fA-F-]{36}/[A-Za-z0-9._-]+$' THEN
    RAISE EXCEPTION 'Invalid storage path';
  END IF;

  INSERT INTO public.submissions (student_name, stage)
  VALUES (trim(p_student_name), p_stage)
  RETURNING id INTO new_submission_id;

  INSERT INTO public.submission_files (submission_id, original_name, storage_path)
  VALUES (new_submission_id, p_original_name, p_storage_path);

  RETURN new_submission_id;
END;
$$;

REVOKE ALL ON FUNCTION public.submit_homework(text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.submit_homework(text,text,text,text) TO anon, authenticated;

-- 5) Allow the browser's publishable key to call only this RPC.
-- No public read/update/delete policies are created.
