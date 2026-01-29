import axios from 'axios';
import type { AnalysisResult } from '../types/analysis';

const API_BASE_URL = 'http://localhost:8080/api';

export const uploadFile = async (file: File): Promise<AnalysisResult> => {
  const formData = new FormData();
  formData.append('file', file);

  const response = await axios.post<AnalysisResult>(
    `${API_BASE_URL}/analyze-report`,
    formData,
    {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    }
  );

  return response.data;
};
