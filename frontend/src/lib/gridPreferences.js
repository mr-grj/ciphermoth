// Remembered per browser. A convenience only, so unavailable storage just means defaults.
const PAGE_SIZE_KEY = "ciphermothVaultPageSize";

export const PAGE_SIZES = [10, 25, 50, 100];
export const DEFAULT_PAGE_SIZE = 25;

export const loadPageSize = () => {
  try {
    const stored = Number(localStorage.getItem(PAGE_SIZE_KEY));
    return PAGE_SIZES.includes(stored) ? stored : DEFAULT_PAGE_SIZE;
  } catch {
    return DEFAULT_PAGE_SIZE;
  }
};

export const savePageSize = (pageSize) => {
  try {
    localStorage.setItem(PAGE_SIZE_KEY, String(pageSize));
  } catch {
    // Keeps the size for this visit only.
  }
};
