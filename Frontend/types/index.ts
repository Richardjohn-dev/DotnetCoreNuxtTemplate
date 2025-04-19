// types/index.ts
export interface ProblemDetails {
  type?: string;
  title?: string;
  status?: number;
  detail?: string;
  instance?: string;
  errors?: Record<string, string[]>; // For validation errors
}

export interface ApiResponse<T> {
  payload: T;
  message?: string;
}

export interface UserInfoResponse {
  userId: string;
  email: string;
  roles: string[];
}

// Add other DTO types used across frontend/backend as needed
