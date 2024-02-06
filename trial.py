import arrow


def human_readable_time_difference(timestamp):
    post_time = arrow.get(timestamp)
    now = arrow.utcnow()

    time_difference = now - post_time

    if time_difference.seconds < 60:
        return f"{time_difference.seconds} seconds ago"
    elif time_difference.seconds < 3600:
        return f"{time_difference.seconds // 60} minutes ago"
    elif time_difference.days == 0:
        return f"{time_difference.seconds // 3600} hours ago"
    elif time_difference.days == 1:
        return "yesterday"
    elif time_difference.days < 7:
        return f"{time_difference.days} days ago"
    else:
        return post_time.format("YYYY-MM-DD HH:mm:ss")


# Example usage
timestamp = "2023-11-10T12:34:56"  # Replace this with your post timestamp
result = human_readable_time_difference(timestamp)
print(result)
